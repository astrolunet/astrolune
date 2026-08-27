/* Socket plumbing for the P2P transport. See net.h for the contract. */

#include "net.h"

#include <stdio.h>
#include <string.h>

#if defined(AL_OS_WINDOWS)
/* winsock2.h must precede windows.h; net.h already ordered that correctly. */
#  include <windows.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <time.h>
#  include <unistd.h>
#endif

/* One uniform snprintf spelling across platforms. */
#if defined(AL_OS_WINDOWS)
#  define net_snprintf sprintf_s
#else
#  define net_snprintf snprintf
#endif

/* Wrap a native descriptor produced by socket()/accept() without an
 * intermediate narrowing cast. */
#if defined(AL_OS_WINDOWS)
static al_socket socket_from_native(SOCKET handle) {
    al_socket s;
    s.handle = handle;
    return s;
}
#else
static al_socket socket_from_native(int handle) {
    al_socket s;
    s.handle = handle;
    return s;
}
#endif

al_bool al_socket_is_open(al_socket s) {
#if defined(AL_OS_WINDOWS)
    return s.handle != INVALID_SOCKET ? AL_TRUE : AL_FALSE;
#else
    return s.handle >= 0 ? AL_TRUE : AL_FALSE;
#endif
}

static int last_error(void) {
#if defined(AL_OS_WINDOWS)
    return WSAGetLastError();
#else
    return errno;
#endif
}

static al_bool would_block(int error) {
#if defined(AL_OS_WINDOWS)
    return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ? AL_TRUE : AL_FALSE;
#else
    return error == EAGAIN || error == EWOULDBLOCK || error == EINPROGRESS
               ? AL_TRUE
               : AL_FALSE;
#endif
}

static void set_non_blocking(al_socket s) {
#if defined(AL_OS_WINDOWS)
    unsigned long mode = 1u;
    (void)ioctlsocket(s.handle, FIONBIO, &mode);
#else
    int flags = fcntl(s.handle, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(s.handle, F_SETFL, flags | O_NONBLOCK);
    }
#endif
}

/* Fill a sockaddr_in from "host", port. NULL host means any-interface. */
static al_status resolve_endpoint(const char *host, al_u16 port,
                                  struct sockaddr_in *out) {
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((unsigned short)port);
    if (host == NULL || host[0] == '\0') {
        out->sin_addr.s_addr = htonl(INADDR_ANY);
        return AL_OK;
    }
    /* Numeric first: peers are usually written as address literals, and this
     * keeps the common path free of resolver dependence. */
#if defined(AL_OS_WINDOWS)
    INT written = InetPtonA(AF_INET, host, &out->sin_addr);
    if (written == 1) return AL_OK;
#else
    if (inet_pton(AF_INET, host, &out->sin_addr) == 1) return AL_OK;
#endif
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = NULL;
    if (getaddrinfo(host, NULL, &hints, &result) != 0 ||
        result == NULL) {
        return AL_ERR_NOT_FOUND;
    }
    *out = *(const struct sockaddr_in *)result->ai_addr;
    out->sin_port = htons((unsigned short)port);
    freeaddrinfo(result);
    return AL_OK;
}

static void format_endpoint(const struct sockaddr_in *address, char *out,
                            al_size cap) {
    if (cap == 0u) return;
    char text[INET_ADDRSTRLEN] = { 0 };
#if defined(AL_OS_WINDOWS)
    (void)InetNtopA(AF_INET, &address->sin_addr, text, sizeof(text));
#else
    (void)inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text));
#endif
    (void)net_snprintf(out, cap, "%s:%u", text,
                       (unsigned)ntohs(address->sin_port));
    out[cap - 1u] = '\0';
}

al_bool al_net_init(void) {
#if defined(AL_OS_WINDOWS)
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0 ? AL_TRUE : AL_FALSE;
#else
    /* Silence the unused-function warning for format_endpoint's helper. */
    return AL_TRUE;
#endif
}

void al_net_shutdown(void) {
#if defined(AL_OS_WINDOWS)
    (void)WSACleanup();
#endif
}

al_status al_net_listen(const char *host, al_u16 port, al_socket *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    out->handle =
#if defined(AL_OS_WINDOWS)
        INVALID_SOCKET;
#else
        -1;
#endif

    struct sockaddr_in address;
    AL_TRY(resolve_endpoint(host, port, &address));

    al_socket s = socket_from_native(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (!al_socket_is_open(s)) return AL_ERR_IO;

    /* Rebinding a restarted node must not wait for lingering TIME_WAIT
     * sockets; devnets restart constantly. */
    int reuse = 1;
    (void)setsockopt(s.handle, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
                     sizeof(reuse));

    if (bind(s.handle, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(s.handle, SOMAXCONN) != 0) {
        al_net_close(s);
        return AL_ERR_IO;
    }
    set_non_blocking(s);
    *out = s;
    return AL_OK;
}

al_status al_net_accept(al_socket listener, al_socket *out, char *endpoint,
                        al_size endpoint_cap) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    out->handle =
#if defined(AL_OS_WINDOWS)
        INVALID_SOCKET;
#else
        -1;
#endif
    struct sockaddr_in peer;
#if defined(AL_OS_WINDOWS)
    int peer_len = (int)sizeof(peer);
#else
    socklen_t peer_len = sizeof(peer);
#endif
    al_socket s = socket_from_native(accept(listener.handle,
                                                 (struct sockaddr *)&peer,
                                                 &peer_len));
    if (!al_socket_is_open(s)) {
        return would_block(last_error()) ? AL_ERR_WOULD_BLOCK : AL_ERR_IO;
    }
    set_non_blocking(s);
    if (endpoint != NULL && endpoint_cap != 0u) {
        format_endpoint(&peer, endpoint, endpoint_cap);
    }
    *out = s;
    return AL_OK;
}

al_status al_net_connect(const char *host, al_u16 port, al_socket *out) {
    if (host == NULL || out == NULL) return AL_ERR_INVALID_ARG;
    out->handle =
#if defined(AL_OS_WINDOWS)
        INVALID_SOCKET;
#else
        -1;
#endif

    struct sockaddr_in address;
    AL_TRY(resolve_endpoint(host, port, &address));

    al_socket s = socket_from_native(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (!al_socket_is_open(s)) return AL_ERR_IO;
    set_non_blocking(s);

    if (connect(s.handle, (const struct sockaddr *)&address,
                sizeof(address)) != 0) {
        if (!would_block(last_error())) {
            al_net_close(s);
            return AL_ERR_IO;
        }
    }
    *out = s;
    return AL_OK;
}

al_status al_net_connect_result(al_socket s) {
    int error = 0;
#if defined(AL_OS_WINDOWS)
    int len = (int)sizeof(error);
#else
    socklen_t len = sizeof(error);
#endif
    if (getsockopt(s.handle, SOL_SOCKET, SO_ERROR, (char *)&error, &len) != 0 ||
        error != 0) {
        return AL_ERR_IO;
    }
    return AL_OK;
}

void al_net_close(al_socket s) {
    if (!al_socket_is_open(s)) return;
#if defined(AL_OS_WINDOWS)
    (void)closesocket(s.handle);
#else
    (void)close(s.handle);
#endif
}

al_status al_net_local_port(al_socket listener, al_u16 *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    struct sockaddr_in address;
#if defined(AL_OS_WINDOWS)
    int length = (int)sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    if (getsockname(listener.handle, (struct sockaddr *)&address, &length) !=
        0) {
        return AL_ERR_IO;
    }
    *out = (al_u16)ntohs(address.sin_port);
    return AL_OK;
}

al_status al_net_recv(al_socket s, al_bytes_mut buffer, al_size *received) {
    if (received == NULL) return AL_ERR_INVALID_ARG;
    *received = 0u;
    if (buffer.len == 0u) return AL_ERR_WOULD_BLOCK;
#if defined(AL_OS_WINDOWS)
    int result = recv(s.handle, (char *)buffer.data, (int)buffer.len, 0);
#else
    ssize_t result = recv(s.handle, buffer.data, buffer.len, 0);
#endif
    if (result == 0) return AL_ERR_CLOSED;
    if (result < 0) {
        return would_block(last_error()) ? AL_ERR_WOULD_BLOCK : AL_ERR_CLOSED;
    }
    *received = (al_size)result;
    return AL_OK;
}

al_status al_net_send(al_socket s, al_bytes data, al_size *sent) {
    if (sent == NULL) return AL_ERR_INVALID_ARG;
    *sent = 0u;
    if (data.len == 0u) return AL_ERR_WOULD_BLOCK;
#if defined(AL_OS_WINDOWS)
    int result = send(s.handle, (const char *)data.data, (int)data.len, 0);
#else
    ssize_t result = send(s.handle, data.data, data.len, 0);
#endif
    if (result < 0) {
        return would_block(last_error()) ? AL_ERR_WOULD_BLOCK : AL_ERR_CLOSED;
    }
    *sent = (al_size)result;
    return AL_OK;
}

al_u64 al_net_now_ms(void) {
#if defined(AL_OS_WINDOWS)
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    if (!QueryPerformanceFrequency(&frequency) ||
        !QueryPerformanceCounter(&counter)) {
        return (al_u64)GetTickCount64();
    }
    return (al_u64)(counter.QuadPart * 1000ull / frequency.QuadPart);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0ull;
    }
    return (al_u64)now.tv_sec * 1000ull + (al_u64)now.tv_nsec / 1000000ull;
#endif
}
void al_net_set_init(al_net_set *set) {
    FD_ZERO(&set->native);
#if !defined(AL_OS_WINDOWS)
    set->max_fd = -1;
#endif
}

void al_net_set_add(al_net_set *set, al_socket s) {
    FD_SET(s.handle, &set->native);
#if !defined(AL_OS_WINDOWS)
    if (s.handle > set->max_fd) set->max_fd = s.handle;
#endif
}

al_bool al_net_set_contains(const al_net_set *set, al_socket s) {
    return FD_ISSET(s.handle, &set->native) ? AL_TRUE : AL_FALSE;
}

int al_net_select(const al_net_set *readable, const al_net_set *writable,
                  al_u32 timeout_ms) {
    /* select() mutates its sets, so hand it copies and keep the caller's view
     * valid for the al_net_set_contains checks afterwards. */
    fd_set read_copy;
    fd_set write_copy;
    fd_set *read_arg = NULL;
    fd_set *write_arg = NULL;
    if (readable != NULL) {
        read_copy = readable->native;
        read_arg = &read_copy;
    }
    if (writable != NULL) {
        write_copy = writable->native;
        write_arg = &write_copy;
    }

    struct timeval timeout;
    timeout.tv_sec = (long)(timeout_ms / 1000u);
    timeout.tv_usec = (long)(timeout_ms % 1000u) * 1000;

#if defined(AL_OS_WINDOWS)
    int nfds = 0; /* ignored on Windows */
#else
    int nfds = 1;
    if (readable != NULL && readable->max_fd + 1 > nfds) {
        nfds = readable->max_fd + 1;
    }
    if (writable != NULL && writable->max_fd + 1 > nfds) {
        nfds = writable->max_fd + 1;
    }
#endif
    return select(nfds, read_arg, write_arg, NULL, &timeout);
}

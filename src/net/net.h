/*
 * Astrolune P2P transport - portable sockets and framed messages.
 *
 * The network layer is deliberately dumb about consensus: it moves canonical
 * bytes between peers and reports what it heard through callbacks. Block and
 * transaction validity stay inside Astrolune::node, so this module can be
 * tested, fuzzed and reused without dragging the state machine along.
 *
 * Three small pieces:
 *
 *   net.c   - sockets: listeners, non-blocking connects, select() polling
 *   wire.c  - the framed message codec shared by every peer
 *   p2p.c   - the peer manager: handshakes, gossip, dedup, timeouts
 */

#ifndef ASTROLUNE_NET_NET_H
#define ASTROLUNE_NET_NET_H

#include "astrolune/base.h"
#include "astrolune/bytes.h"

#if defined(AL_OS_WINDOWS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/select.h>
#  include <sys/socket.h>
#endif

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * Process-wide initialisation
 * -------------------------------------------------------------------------- */

/* Must succeed once before any socket call. Windows requires WSAStartup;
 * other platforms do nothing. Safe to call more than once. */
AL_NODISCARD al_bool al_net_init(void);
void al_net_shutdown(void);

/* A socket handle. Wrapped in a struct so an uninitialised value cannot be
 * confused with a valid descriptor on either platform. */
typedef struct al_socket {
#if defined(AL_OS_WINDOWS)
    SOCKET handle;
#else
    int handle;
#endif
} al_socket;

#if defined(AL_OS_WINDOWS)
#  define AL_SOCKET_INVALID { INVALID_SOCKET }
#else
#  define AL_SOCKET_INVALID { (-1) }
#endif

AL_NODISCARD al_bool al_socket_is_open(al_socket s);

/* --------------------------------------------------------------------------
 * Listeners and connections
 *
 * Every socket returned here is non-blocking; callers drive them through
 * al_net_select and never block on I/O.
 * -------------------------------------------------------------------------- */

/* Bind and listen. `host` may be NULL for any-interface (INADDR_ANY). */
AL_NODISCARD al_status al_net_listen(const char *host, al_u16 port,
                                     al_socket *out);

/* Accept one pending connection. Returns AL_ERR_NOT_FOUND when no connection
 * is waiting, which is how the poller treats "listener not readable". */
AL_NODISCARD al_status al_net_accept(al_socket listener, al_socket *out,
                                     char *endpoint, al_size endpoint_cap);

/* Begin a non-blocking connection; completion is observed as writability. */
AL_NODISCARD al_status al_net_connect(const char *host, al_u16 port,
                                      al_socket *out);

/* Check a connecting socket. AL_OK means established, AL_ERR_IO means the
 * attempt failed and the socket must be closed. */
AL_NODISCARD al_status al_net_connect_result(al_socket s);

void al_net_close(al_socket s);

/* The locally bound port of a listener. Lets tests and daemons bind port 0
 * (an OS-assigned ephemeral) and still learn what to advertise. */
AL_NODISCARD al_status al_net_local_port(al_socket listener, al_u16 *out);

/*
 * Receive and send. Both report partial progress through their out-parameter
 * and return AL_ERR_WOULD_BLOCK when nothing could move. A receive of zero
 * bytes means orderly shutdown and returns AL_ERR_CLOSED.
 *
 * These two are local to the transport: the public status vocabulary describes
 * consensus outcomes, and "the peer's TCP window is full" is not one.
 */
#define AL_ERR_WOULD_BLOCK ((al_status)(-1))
#define AL_ERR_CLOSED      ((al_status)(-2))

AL_NODISCARD al_status al_net_recv(al_socket s, al_bytes_mut buffer,
                                   al_size *received);
AL_NODISCARD al_status al_net_send(al_socket s, al_bytes data, al_size *sent);

/* --------------------------------------------------------------------------
 * Polling
 *
 * Thin wrappers over select(). Sets are rebuilt on every tick, which is the
 * right trade at peer counts a few hundred and keeps the API platform-free.
 * -------------------------------------------------------------------------- */

typedef struct al_net_set {
    fd_set   native;
#if !defined(AL_OS_WINDOWS)
    int      max_fd;
#endif
} al_net_set;

void al_net_set_init(al_net_set *set);
void al_net_set_add(al_net_set *set, al_socket s);
AL_NODISCARD al_bool al_net_set_contains(const al_net_set *set, al_socket s);

/* Wait up to timeout_ms for readiness. Returns the number of ready sockets. */
AL_NODISCARD int al_net_select(const al_net_set *readable,
                               const al_net_set *writable, al_u32 timeout_ms);

/* Monotonic milliseconds since an arbitrary fixed point. Never goes backwards;
 * used for every timeout in this module. */
AL_NODISCARD al_u64 al_net_now_ms(void);

AL_EXTERN_C_END

#endif /* ASTROLUNE_NET_NET_H */

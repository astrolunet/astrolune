/* JSON-RPC over HTTP/1.1. See server.h for the contract. */

#include "server.h"
#include "internal/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char HTTP_RESPONSE_HEADER[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %llu\r\n"
    "Connection: close\r\n"
    "\r\n";

static al_socket invalid_socket(void) {
#if defined(AL_OS_WINDOWS)
    al_socket s = { INVALID_SOCKET };
#else
    al_socket s = { -1 };
#endif
    return s;
}

/* Case-insensitive substring search over the header block only. */
static const char *find_header(const char *headers, al_size headers_len,
                               const char *name) {
    al_size name_len = strlen(name);
    for (al_size i = 0u; i + name_len < headers_len; ++i) {
        al_size j = 0u;
        while (j < name_len) {
            char a = headers[i + j];
            char b = name[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
            j++;
        }
        if (j == name_len) return headers + i + name_len;
    }
    return NULL;
}

/* Parse "Content-Length" out of a complete header block. */
static al_status parse_content_length(const char *request, al_size limit,
                                      al_size *out) {
    const char *body = strstr(request, "\r\n\r\n");
    if (body == NULL || (al_size)(body - request) > limit) {
        return AL_ERR_TRUNCATED;
    }
    const char *value =
        find_header(request, (al_size)(body - request), "content-length:");
    if (value == NULL) return AL_ERR_MALFORMED;
    while (*value == ' ') value++;

    al_size length = 0u;
    if (*value < '0' || *value > '9') return AL_ERR_MALFORMED;
    while (*value >= '0' && *value <= '9') {
        length = length * 10u + (al_size)(*value - '0');
        if (length > AL_RPC_MAX_REQUEST) return AL_ERR_OUT_OF_RANGE;
        value++;
    }
    *out = length;
    return AL_OK;
}

/* --- Client lifecycle ------------------------------------------------------------ */

static void client_init(al_rpc_client *client) {
    al_memzero(client, sizeof(*client));
    client->socket = invalid_socket();
}

static void client_close(al_rpc_server *server, al_size index) {
    al_rpc_client *client = &server->clients[index];
    al_net_close(client->socket);
    free(client->buffer);
    client_init(client);
}

static void client_send_all(al_rpc_client *client, const char *text) {
    /* Short writes on a fresh connection mean the peer is gone or stalled;
     * dropping both is correct for an RPC nobody will read. */
    al_bytes remaining = al_bytes_make((const al_u8 *)text, strlen(text));
    while (remaining.len != 0u) {
        al_size sent = 0u;
        if (al_net_send(client->socket, remaining, &sent) != AL_OK ||
            sent == 0u) {
            return;
        }
        remaining = al_bytes_slice(remaining, sent, remaining.len - sent);
    }
}

/* --- Bearer token authentication ----------------------------------------------- */

static al_bool check_bearer_token(const al_rpc_server *server,
                                  const char *headers, al_size headers_len) {
    /* If no token is configured, allow all requests. */
    if (server->auth_token == NULL || server->auth_token_len == 0u) {
        return AL_TRUE;
    }

    /* Find "Authorization:" header (case-insensitive). */
    const char *auth_value = find_header(headers, headers_len, "authorization:");
    if (auth_value == NULL) return AL_FALSE;

    /* Skip whitespace. */
    while (*auth_value == ' ' || *auth_value == '\t') auth_value++;

    /* Check for "Bearer " prefix (case-insensitive). */
    static const char BEARER[] = "Bearer ";
    for (al_size i = 0u; i < sizeof(BEARER) - 1u; i++) {
        char a = auth_value[i];
        char b = BEARER[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return AL_FALSE;
    }
    const char *token_start = auth_value + sizeof(BEARER) - 1u;

    /* Find end of token (CRLF or end of headers). */
    const char *token_end = token_start;
    while (*token_end != '\0' && *token_end != '\r' && *token_end != '\n') {
        token_end++;
    }

    al_size provided_len = (al_size)(token_end - token_start);
    if (provided_len != server->auth_token_len) return AL_FALSE;

    /* Constant-time comparison to avoid timing side-channels. */
    al_u8 diff = 0u;
    for (al_size i = 0u; i < server->auth_token_len; i++) {
        diff |= (al_u8)((al_u8)token_start[i] ^ server->auth_token[i]);
    }
    return (diff == 0u) ? AL_TRUE : AL_FALSE;
}

/* --- Request dispatch ------------------------------------------------------------ */

/*
 * Assemble the JSON-RPC envelope around what the handler produced. The id is
 * captured up front so a mid-flight handler failure still yields a well-formed
 * error envelope rather than a truncated response.
 */
static void capture_id(const al_json_value *request, al_json_writer *id) {
    const al_json_value *value = al_json_get(request, "id");
    if (value == NULL || value->kind == AL_JSON_NULL) {
        al_json_writer_raw(id, "null");
    } else if (value->kind == AL_JSON_STRING) {
        al_json_writer_string(id, value->string);
    } else if (value->kind == AL_JSON_U64) {
        al_json_writer_u64(id, value->u64_value);
    } else if (value->kind == AL_JSON_I64) {
        al_json_writer_i64(id, value->i64_value);
    } else {
        al_json_writer_raw(id, "null");
    }
}

static void respond_error_body(al_json_writer *writer, int code,
                               const char *message) {
    al_json_writer_raw(writer, "\"error\":{\"code\":");
    al_json_writer_i64(writer, code);
    al_json_writer_raw(writer, ",\"message\":");
    al_json_writer_string(writer, message);
    al_json_writer_raw(writer, "}");
}

static void send_response(al_rpc_client *client, const al_json_writer *body) {
    const char *text = al_json_writer_text(body);
    char header[160];
    int header_len = (int)snprintf(header, sizeof(header),
                                   HTTP_RESPONSE_HEADER,
                                   (unsigned long long)strlen(text));
    if (header_len > 0 && (al_size)header_len < sizeof(header)) {
        client_send_all(client, header);
        client_send_all(client, text);
    }
}

static void dispatch_request(al_rpc_server *server, al_size index) {
    al_rpc_client *client = &server->clients[index];

    /* Find the header/body boundary. */
    const char *header_end =
        strstr((const char *)client->buffer, "\r\n\r\n");
    if (header_end == NULL) {
        client_close(server, index);
        return;
    }

    /* Check bearer token authentication before parsing JSON. */
    if (!check_bearer_token(server, (const char *)client->buffer,
                            (al_size)(header_end - (const char *)client->buffer))) {
        /* Send 401 Unauthorized response. */
        static const char AUTH_ERROR[] =
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 80\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,"
            "\"message\":\"authentication required\"}}";
        client_send_all(client, AUTH_ERROR);
        client_close(server, index);
        return;
    }

    const char *body_start = header_end + 4u;

    al_json_value *request = NULL;
    al_status parse_status = al_json_parse(body_start, &request);

    al_json_writer id;
    al_json_writer_init(&id);
    /* Absent or unparsable requests still answer with a well-formed
     * envelope; a successful parse replaces this default. */
    al_json_writer_raw(&id, "null");

    al_json_writer body;
    al_json_writer_init(&body);

    if (parse_status != AL_OK) {
        respond_error_body(&body, -32700, "parse error");
    } else {
        /* Replace the default null id captured before parsing. */
        id.len = 0u;
        if (id.data != NULL) id.data[0] = '\0';
        capture_id(request, &id);
        al_status handled =
            server->handler(server->userdata, request, &body);
        if (handled != AL_OK) {
            al_json_writer_free(&body);
            al_json_writer_init(&body);
            respond_error_body(&body, -32603, "internal error");
        } else if (strncmp(al_json_writer_text(&body), "\"error\":", 8u) ==
                   0) {
            /* Handler already wrote an error member verbatim; pass through. */
        } else {
            /* Wrap whatever the handler wrote as the result member. */
            al_json_writer wrapped;
            al_json_writer_init(&wrapped);
            al_json_writer_raw(&wrapped, "\"result\":");
            al_json_writer_raw(&wrapped, al_json_writer_text(&body));
            al_json_writer_free(&body);
            body = wrapped;
        }
    }

    al_json_writer envelope;
    al_json_writer_init(&envelope);
    al_json_writer_raw(&envelope, "{\"jsonrpc\":\"2.0\",\"id\":");
    al_json_writer_raw(&envelope, al_json_writer_text(&id));
    al_json_writer_raw(&envelope, ",");
    al_json_writer_raw(&envelope, al_json_writer_text(&body));
    al_json_writer_raw(&envelope, "}");

    send_response(client, &envelope);

    al_json_free(request);
    al_json_writer_free(&id);
    al_json_writer_free(&body);
    al_json_writer_free(&envelope);
    client_close(server, index);
}

static void client_readable(al_rpc_server *server, al_size index) {
    al_rpc_client *client = &server->clients[index];
    for (;;) {
        /* Keep one spare byte for the terminator written below. */
        if (client->buffer_cap <= client->buffer_len + 1u) {
            if (client->buffer_cap >= AL_RPC_MAX_REQUEST) {
                client_close(server, index); /* oversized request */
                return;
            }
            al_size new_cap = client->buffer_cap != 0u
                                  ? client->buffer_cap * 2u
                                  : 4096u;
            if (new_cap > AL_RPC_MAX_REQUEST) new_cap = AL_RPC_MAX_REQUEST;
            al_u8 *grown = (al_u8 *)realloc(client->buffer, new_cap);
            if (grown == NULL) {
                client_close(server, index);
                return;
            }
            client->buffer = grown;
            client->buffer_cap = new_cap;
        }

        al_size received = 0u;
        al_bytes_mut room = { client->buffer + client->buffer_len,
                              client->buffer_cap - client->buffer_len - 1u };
        al_status status = al_net_recv(client->socket, room, &received);
        if (status == AL_ERR_WOULD_BLOCK) return;
        if (status == AL_ERR_CLOSED) {
            client_close(server, index);
            return;
        }
        client->buffer_len += received;
        client->last_activity_ms = al_net_now_ms();

        /* A complete request is headers plus exactly Content-Length bytes. */
        const char *body = strstr((const char *)client->buffer, "\r\n\r\n");
        if (body == NULL) continue;
        al_size head_len = (al_size)(body - (const char *)client->buffer) + 4u;
        al_size content_length = 0u;
        if (parse_content_length((const char *)client->buffer, head_len,
                                 &content_length) == AL_OK &&
            client->buffer_len >= head_len + content_length) {
            client->buffer[client->buffer_len] = '\0';
            dispatch_request(server, index);
            return;
        }
    }
}

/* --- Public API ---------------------------------------------------------------------- */

al_status al_rpc_server_init(al_rpc_server *server, const char *host,
                             al_u16 port, al_rpc_handler_fn handler,
                             void *userdata) {
    if (server == NULL || handler == NULL) return AL_ERR_INVALID_ARG;
    al_memzero(server, sizeof(*server));
    server->handler = handler;
    server->userdata = userdata;
    for (al_size i = 0u; i < AL_RPC_MAX_CLIENTS; ++i) {
        client_init(&server->clients[i]);
    }
    al_status status = al_net_listen(host, port, &server->listener);
    if (status == AL_OK) {
        server->has_listener = AL_TRUE;
    } else {
        server->listener = invalid_socket();
    }
    return status;
}

void al_rpc_server_set_token(al_rpc_server *server,
                             const al_u8 *token, al_size token_len) {
    if (server == NULL) return;
    server->auth_token = token;
    server->auth_token_len = token_len;
}

void al_rpc_server_close(al_rpc_server *server) {
    if (server == NULL) return;
    for (al_size i = 0u; i < AL_RPC_MAX_CLIENTS; ++i) {
        client_close(server, i);
    }
    if (server->has_listener) {
        al_net_close(server->listener);
        server->has_listener = AL_FALSE;
    }
}

void al_rpc_poll(al_rpc_server *server, al_u32 timeout_ms) {
    if (server == NULL || !server->has_listener) return;

    /* Reap incomplete requests even when the caller uses a zero-timeout poll.
     * This keeps slow-client slots bounded independently of socket activity. */
    al_u64 now_ms = al_net_now_ms();
    for (al_size i = 0u; i < AL_RPC_MAX_CLIENTS; ++i) {
        al_rpc_client *client = &server->clients[i];
        if (al_socket_is_open(client->socket) &&
            now_ms - client->last_activity_ms > AL_RPC_CLIENT_TIMEOUT_MS) {
            client_close(server, i);
        }
    }

    al_net_set readable;
    al_net_set_init(&readable);
    al_net_set_add(&readable, server->listener);
    for (al_size i = 0u; i < AL_RPC_MAX_CLIENTS; ++i) {
        if (al_socket_is_open(server->clients[i].socket)) {
            al_net_set_add(&readable, server->clients[i].socket);
        }
    }
    if (al_net_select(&readable, NULL, timeout_ms) <= 0) return;

    if (al_net_set_contains(&readable, server->listener)) {
        for (al_size i = 0u; i < AL_RPC_MAX_CLIENTS; ++i) {
            if (al_socket_is_open(server->clients[i].socket)) continue;
            al_socket accepted = invalid_socket();
            if (al_net_accept(server->listener, &accepted, NULL, 0u) != AL_OK) {
                break;
            }
            server->clients[i].socket = accepted;
            server->clients[i].last_activity_ms = al_net_now_ms();
        }
    }

    for (al_size i = 0u; i < AL_RPC_MAX_CLIENTS; ++i) {
        if (al_socket_is_open(server->clients[i].socket) &&
            al_net_set_contains(&readable, server->clients[i].socket)) {
            client_readable(server, i);
        }
    }
}

al_status al_rpc_respond_result(al_json_writer *response,
                                const char *result_json) {
    if (response == NULL || result_json == NULL) return AL_ERR_INVALID_ARG;
    al_json_writer_raw(response, "\"result\":");
    al_json_writer_raw(response, result_json);
    return al_json_writer_finish(response);
}

al_status al_rpc_respond_error(al_json_writer *response, int code,
                               const char *message) {
    if (response == NULL || message == NULL) return AL_ERR_INVALID_ARG;
    respond_error_body(response, code, message);
    return al_json_writer_finish(response);
}

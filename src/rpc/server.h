/*
 * JSON-RPC 2.0 server over a minimal HTTP/1.1 listener.
 *
 * The surface is intentionally tiny: one port, POST requests with a JSON
 * body, responses always Connection: close so no connection state machine is
 * needed. That is enough for wallets, explorers and `curl`, which is exactly
 * the audience at this stage of the network; a hardened public endpoint would
 * sit behind a reverse proxy anyway.
 */

#ifndef ASTROLUNE_RPC_SERVER_H
#define ASTROLUNE_RPC_SERVER_H

#include "net.h"
#include "json.h"

AL_EXTERN_C_BEGIN

#define AL_RPC_MAX_REQUEST (1024u * 1024u)
#define AL_RPC_MAX_CLIENTS 32u
#define AL_RPC_CLIENT_TIMEOUT_MS 10000u

typedef struct al_rpc_client {
    al_socket socket;
    al_bool   in_use;
    /* Accumulated request bytes. Grown on demand, bounded by
     * AL_RPC_MAX_REQUEST; larger requests drop the connection. */
    al_u8    *buffer;
    al_size   buffer_cap;
    al_size   buffer_len;
    al_u64    last_activity_ms;
} al_rpc_client;

/*
 * Handle one parsed JSON-RPC request. Implementations append either the
 * result VALUE (bare JSON, no "result": key) or call al_rpc_respond_error to
 * append an error member; the envelope is assembled by the server.
 */
typedef al_status (*al_rpc_handler_fn)(void *userdata,
                                       const al_json_value *request,
                                       al_json_writer *body);

typedef struct al_rpc_server {
    al_socket       listener;
    al_bool         has_listener;
    al_rpc_handler_fn handler;
    void           *userdata;
    al_rpc_client   clients[AL_RPC_MAX_CLIENTS];
} al_rpc_server;

AL_NODISCARD al_status al_rpc_server_init(al_rpc_server *server,
                                          const char *host, al_u16 port,
                                          al_rpc_handler_fn handler,
                                          void *userdata);
void al_rpc_server_close(al_rpc_server *server);

/* One service tick: accept, read, dispatch complete requests, respond. */
void al_rpc_poll(al_rpc_server *server, al_u32 timeout_ms);

/* Helper for handlers: wrap a payload as a successful JSON-RPC result. */
AL_NODISCARD al_status al_rpc_respond_result(al_json_writer *response,
                                             const char *result_json);
/* Helper for handlers: emit a JSON-RPC error object. */
AL_NODISCARD al_status al_rpc_respond_error(al_json_writer *response,
                                            int code, const char *message);

AL_EXTERN_C_END

#endif /* ASTROLUNE_RPC_SERVER_H */

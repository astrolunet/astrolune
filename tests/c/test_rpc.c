/*
 * JSON codec and RPC server tests.
 *
 * The server test runs a real HTTP round trip over loopback using a raw
 * socket client, so header parsing, body framing and the JSON-RPC envelope
 * are all exercised end to end.
 */

#include "altest.h"
#include "json.h"
#include "server.h"

/* ------------------------------------------------------------------ */
/* JSON parser                                                         */
/* ------------------------------------------------------------------ */

AL_TEST(json_parse_scalars) {
    al_json_value *value = NULL;

    AL_CHECK_EQ_STATUS(al_json_parse("null", &value), AL_OK);
    AL_CHECK(value->kind == AL_JSON_NULL);
    al_json_free(value);

    AL_CHECK_EQ_STATUS(al_json_parse("true", &value), AL_OK);
    AL_CHECK(value->kind == AL_JSON_TRUE);
    al_json_free(value);

    AL_CHECK_EQ_STATUS(al_json_parse("42", &value), AL_OK);
    AL_CHECK_EQ_U64(value->u64_value, 42u);
    al_json_free(value);

    AL_CHECK_EQ_STATUS(al_json_parse("-7", &value), AL_OK);
    AL_CHECK_EQ_I64(value->i64_value, -7);
    al_json_free(value);

    /* Floating point never enters consensus arithmetic; reject it. */
    AL_CHECK_EQ_STATUS(al_json_parse("1.5", &value), AL_ERR_UNSUPPORTED);
    AL_CHECK_EQ_STATUS(al_json_parse("1e3", &value), AL_ERR_UNSUPPORTED);
}

AL_TEST(json_parse_strings_and_escapes) {
    al_json_value *value = NULL;
    AL_CHECK_EQ_STATUS(al_json_parse("\"hi\\n\\t\\\"q\\\\\"", &value),
                       AL_OK);
    AL_CHECK_EQ_STR(value->string, "hi\n\t\"q\\");
    al_json_free(value);

    /* \u00e9 encodes as two UTF-8 bytes. */
    AL_CHECK_EQ_STATUS(al_json_parse("\"\\u00e9\"", &value), AL_OK);
    AL_CHECK_HEX(value->string, 2u, "c3a9");
    al_json_free(value);
}

AL_TEST(json_parse_objects_and_lookup) {
    const char *text =
        "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"get_info\","
        "\"params\":{\"address\":\"0xab\",\"flag\":true}}";
    al_json_value *value = NULL;
    AL_CHECK_EQ_STATUS(al_json_parse(text, &value), AL_OK);

    AL_CHECK_EQ_STR(al_json_as_string(al_json_get(value, "method")),
                    "get_info");
    const al_json_value *params = al_json_get(value, "params");
    AL_CHECK(params != NULL && params->kind == AL_JSON_OBJECT);
    AL_CHECK_EQ_STR(
        al_json_as_string(al_json_get(params, "address")), "0xab");

    al_u64 id = 0u;
    AL_CHECK(al_json_as_u64(al_json_get(value, "id"), &id));
    AL_CHECK_EQ_U64(id, 17u);

    AL_CHECK(al_json_get(value, "missing") == NULL);
    al_json_free(value);
}

AL_TEST(json_rejects_malformed_input) {
    al_json_value *value = NULL;
    AL_CHECK_EQ_STATUS(al_json_parse("{", &value), AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_json_parse("{\"a\":}", &value), AL_ERR_MALFORMED);
    AL_CHECK_EQ_STATUS(al_json_parse("\"unterminated", &value),
                       AL_ERR_TRUNCATED);
    AL_CHECK_EQ_STATUS(al_json_parse("{} trailing", &value),
                       AL_ERR_TRAILING_BYTES);
    AL_CHECK(value == NULL);
}

/* ------------------------------------------------------------------ */
/* JSON writer                                                         */
/* ------------------------------------------------------------------ */

AL_TEST(json_writer_shapes) {
    al_json_writer writer;
    al_json_writer_init(&writer);
    al_json_writer_raw(&writer, "{\"balance\":");
    al_json_writer_u64(&writer, 1234567890123ull);
    al_json_writer_raw(&writer, ",\"name\":");
    al_json_writer_string(&writer, "node\"1\n");
    al_json_writer_raw(&writer, ",\"hash\":");
    static const al_u8 bytes[] = { 0xdeu, 0xadu, 0x01u };
    al_json_writer_hex(&writer, al_bytes_make(bytes, sizeof(bytes)));
    al_json_writer_raw(&writer, "}");
    AL_CHECK_EQ_STATUS(al_json_writer_finish(&writer), AL_OK);

    AL_CHECK_EQ_STR(al_json_writer_text(&writer),
                    "{\"balance\":1234567890123,\"name\":"
                    "\"node\\\"1\\n\",\"hash\":\"0xdead01\"}");
    al_json_writer_free(&writer);
}

/* ------------------------------------------------------------------ */
/* RPC server over loopback                                            */
/* ------------------------------------------------------------------ */

static al_status counting_handler(void *userdata,
                                  const al_json_value *request,
                                  al_json_writer *body) {
    al_size *calls = (al_size *)userdata;
    (*calls)++;
    const char *method = al_json_as_string(al_json_get(request, "method"));
    if (method != NULL && strcmp(method, "ping") == 0) {
        /* Handlers emit the bare result value; the server wraps it. */
        al_json_writer_raw(body, "{\"pong\":true}");
        return AL_OK;
    }
    if (method != NULL && strcmp(method, "boom") == 0) {
        return AL_ERR_INVALID_ARG; /* handler failure path */
    }
    return al_rpc_respond_error(body, -32601, "method not found");
}

/* Minimal cooperative HTTP client: sends one request, pumping the server
 * between receive attempts, and returns the response body after the header
 * break (the server always answers Connection: close). Every stage carries a
 * hard iteration budget so a regression hangs one test, not the suite. */
#define HTTP_BUDGET 1000u

static al_bool http_round_trip(al_rpc_server *server, al_u16 port,
                               const char *body, char *out, al_size cap) {
    AL_UNUSED(port);
    al_socket socket;
    if (al_net_connect("127.0.0.1", port, &socket) != AL_OK) {
        return AL_FALSE;
    }

    char request[2048];
    int length =
        snprintf(request, sizeof(request),
                 "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
                 "application/json\r\nContent-Length: %llu\r\n\r\n%s",
                 (unsigned long long)strlen(body), body);
    if (length <= 0 || (al_size)length >= sizeof(request)) {
        al_net_close(socket);
        return AL_FALSE;
    }

    /* Push the request out, pumping the server whenever the socket is not
     * ready yet (non-blocking connect, backlog, window). */
    al_bytes remaining = al_bytes_make(request, (al_size)length);
    for (al_u32 attempts = 0u;
         remaining.len != 0u && attempts < HTTP_BUDGET; ++attempts) {
        al_size sent = 0u;
        al_status status = al_net_send(socket, remaining, &sent);
        if (status == AL_OK && sent != 0u) {
            remaining = al_bytes_slice(remaining, sent,
                                       remaining.len - sent);
            continue;
        }
        al_rpc_poll(server, 2u);
    }
    if (remaining.len != 0u) {
        al_net_close(socket);
        return AL_FALSE;
    }

    /* Pump the server and read until it closes the connection. */
    al_size total = 0u;
    for (al_u32 attempts = 0u; attempts < HTTP_BUDGET; ++attempts) {
        al_u8 chunk[4096];
        al_size received = 0u;
        al_status status =
            al_net_recv(socket, (al_bytes_mut){ chunk, sizeof(chunk) },
                        &received);
        if (status == AL_OK && received != 0u) {
            if (total + received < cap) {
                memcpy(out + total, chunk, received);
                total += received;
            }
            attempts = 0u; /* keep reading while data flows */
            continue;
        }
        if (status == AL_ERR_CLOSED) break;
        al_rpc_poll(server, 2u);
    }
    al_net_close(socket);

    const char *split = strstr(out, "\r\n\r\n");
    if (split == NULL || total == 0u) return AL_FALSE;
    /* The received stream is not NUL-terminated by anyone else. */
    out[total] = '\0';
    memmove(out, split + 4u, strlen(split + 4u) + 1u);
    return AL_TRUE;
}

AL_TEST(rpc_server_http_round_trip) {
    AL_CHECK(al_net_init());

    al_rpc_server server;
    al_size calls = 0u;
    AL_CHECK_EQ_STATUS(
        al_rpc_server_init(&server, "127.0.0.1", 0u, counting_handler,
                           &calls),
        AL_OK);
    al_u16 port = 0u;
    AL_CHECK_EQ_STATUS(al_net_local_port(server.listener, &port), AL_OK);

    char response[4096];
    AL_CHECK(http_round_trip(&server, port,
                             "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":"
                             "\"ping\"}",
                             response, sizeof(response)));
    AL_CHECK_EQ_STR(response, "{\"jsonrpc\":\"2.0\",\"id\":5,"
                              "\"result\":{\"pong\":true}}");
    AL_CHECK_EQ_U64((al_u64)calls, 1u);

    /* Unknown methods produce the standard error envelope. */
    AL_CHECK(http_round_trip(&server, port,
                             "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":"
                             "\"nope\"}",
                             response, sizeof(response)));
    AL_CHECK(strstr(response, "\"error\":{\"code\":-32601") != NULL);

    /* A handler that fails still yields a well-formed internal error. */
    AL_CHECK(http_round_trip(&server, port,
                             "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":"
                             "\"boom\"}",
                             response, sizeof(response)));
    AL_CHECK(strstr(response, "-32603") != NULL);

    /* Malformed JSON yields a parse error, not a crash. */
    AL_CHECK(http_round_trip(&server, port, "{not json", response,
                             sizeof(response)));
    AL_CHECK(strstr(response, "-32700") != NULL);

    al_rpc_server_close(&server);
}

static const char *AL_TEST_SUITE_NAME = "rpc";

AL_TEST_MAIN {
    AL_RUN(json_parse_scalars);
    AL_RUN(json_parse_strings_and_escapes);
    AL_RUN(json_parse_objects_and_lookup);
    AL_RUN(json_rejects_malformed_input);
    AL_RUN(json_writer_shapes);
    AL_RUN(rpc_server_http_round_trip);
}

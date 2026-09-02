/* P2P callbacks: transaction/block ingestion and peer lifecycle. */

#include "internal.h"

al_bool daemon_on_transaction(void *userdata, al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    al_hash256 hash;
    return al_node_submit_transaction(&daemon->node, encoded, &hash) == AL_OK
               ? AL_TRUE
               : AL_FALSE;
}

al_bool daemon_on_block(void *userdata, al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    if (daemon->consensus_ready) {
        return AL_FALSE;
    }
    al_status status =
        al_node_accept_encoded_block(&daemon->node, encoded);
    if (status != AL_OK) {
        if (status != AL_ERR_ALREADY_EXISTS) {
            char message[160];
            (void)snprintf(message, sizeof(message),
                           "block rejected: %s", al_status_str(status));
            DAEMON_LOG(daemon, message);
        }
        return AL_FALSE;
    }
    if (daemon->config.data_dir != NULL &&
        al_node_storage_commit_block(&daemon->storage, &daemon->state,
                                     encoded) != AL_OK) {
        DAEMON_LOG(daemon, "storage commit failed; stopping for recovery");
        daemon->stop_requested = AL_TRUE;
        return AL_FALSE;
    }
    if (daemon->node.has_head) {
        char message[96];
        (void)snprintf(message, sizeof(message), "accepted block %llu",
                       (unsigned long long)daemon->node.head.height);
        DAEMON_LOG(daemon, message);
    }
    return AL_TRUE;
}

al_status daemon_read_block(void *userdata, al_height height,
                            al_bytes_mut buffer, al_size *written) {
    al_daemon *daemon = (al_daemon *)userdata;
    return al_node_storage_read_block(&daemon->storage, height, buffer,
                                      written);
}

al_status daemon_read_finalized_block(
    void *userdata, al_height height, al_bytes_mut buffer, al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    al_daemon *daemon = (al_daemon *)userdata;
    al_size certificate_size = 0u;
    al_status status = al_node_storage_read_finality(
        &daemon->storage, height, (al_bytes_mut){ NULL, 0u },
        &certificate_size);
    if (status != AL_ERR_BUFFER_TOO_SMALL) return status;
    al_size block_size = 0u;
    status = al_node_storage_read_block(
        &daemon->storage, height, (al_bytes_mut){ NULL, 0u }, &block_size);
    if (status != AL_ERR_BUFFER_TOO_SMALL) return status;
    al_size required = al_varint_size(certificate_size) + certificate_size +
                       al_varint_size(block_size) + block_size;
    *written = required;
    if (required > AL_WIRE_MAX_PAYLOAD) return AL_ERR_OUT_OF_RANGE;
    if (buffer.data == NULL || buffer.len < required) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    al_writer writer;
    al_writer_init(&writer, buffer.data, buffer.len);
    al_writer_varint(&writer, certificate_size);
    al_size stored = 0u;
    AL_TRY(al_node_storage_read_finality(
        &daemon->storage, height,
        (al_bytes_mut){ writer.data + writer.pos, writer.cap - writer.pos },
        &stored));
    writer.pos += stored;
    al_writer_varint(&writer, block_size);
    AL_TRY(al_node_storage_read_block(
        &daemon->storage, height,
        (al_bytes_mut){ writer.data + writer.pos, writer.cap - writer.pos },
        &stored));
    writer.pos += stored;
    AL_TRY(al_writer_finish(&writer));
    *written = al_writer_len(&writer);
    return AL_OK;
}

al_height daemon_known_blocks(void *userdata) {
    al_daemon *daemon = (al_daemon *)userdata;
    return daemon->node.has_head ? daemon->node.head.height + 1u : 0u;
}

void daemon_peer_up(void *userdata, const al_p2p_peer *peer) {
    al_daemon *daemon = (al_daemon *)userdata;
    char message[160];
    (void)snprintf(message, sizeof(message), "peer up: %s (%llu known)",
                   peer->endpoint, (unsigned long long)peer->height);
    DAEMON_LOG(daemon, message);
}

void daemon_peer_down(void *userdata, const char *endpoint) {
    al_daemon *daemon = (al_daemon *)userdata;
    char message[160];
    (void)snprintf(message, sizeof(message), "peer down: %s", endpoint);
    DAEMON_LOG(daemon, message);
}

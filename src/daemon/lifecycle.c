/* Daemon lifecycle: open, close, scratch cleanup. */

#include "internal.h"

void daemon_free_scratch(al_daemon *daemon) {
    free(daemon->mempool_entries);
    free(daemon->mempool_bytes);
    free(daemon->round_mempool_entries);
    free(daemon->round_mempool_bytes);
    free(daemon->block_transactions);
    free(daemon->receipts);
    free(daemon->block_scratch);
    free(daemon->pending_block);
    daemon->mempool_entries = NULL;
    daemon->mempool_bytes = NULL;
    daemon->round_mempool_entries = NULL;
    daemon->round_mempool_bytes = NULL;
    daemon->block_transactions = NULL;
    daemon->receipts = NULL;
    daemon->block_scratch = NULL;
    daemon->pending_block = NULL;
}

al_status al_daemon_open(const al_daemon_config *config,
                         const char *genesis_path, al_daemon **out) {
    if (config == NULL || config->data_dir == NULL || genesis_path == NULL ||
        out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (!al_crypto_is_secure() && !config->allow_insecure_crypto) {
        return AL_ERR_UNSUPPORTED;
    }
    *out = NULL;

    al_daemon *daemon = (al_daemon *)calloc(1u, sizeof(*daemon));
    if (daemon == NULL) return AL_ERR_OUT_OF_MEMORY;
    daemon->config = *config;
    if (daemon->config.round_timeout_ms == 0u) {
        daemon->config.round_timeout_ms = 6000u;
    }
    if (daemon->config.enable_rpc && daemon->config.rpc_host == NULL) {
        daemon->config.rpc_host = "127.0.0.1";
    }

    al_u8 *genesis_bytes = NULL;
    al_size genesis_size = 0u;
    al_status status = read_whole_file(genesis_path, &genesis_bytes,
                                       &genesis_size, 1024u * 1024u);
    if (status == AL_OK) {
        status = al_genesis_decode(al_bytes_make(genesis_bytes, genesis_size),
                                   daemon->allocations,
                                   AL_COUNTOF(daemon->allocations),
                                   &daemon->genesis);
    }
    free(genesis_bytes);
    if (status != AL_OK) goto fail;
    {
        al_hash256 genesis_hash;
        al_genesis_hash(&daemon->genesis, &genesis_hash);
        al_hash_to_hex(&genesis_hash, daemon->genesis_hex);
    }

    status = al_arena_init(&daemon->state_arena, 1024u * 1024u);
    if (status == AL_OK) {
        status = al_node_storage_open(&daemon->storage,
                                      daemon->config.data_dir,
                                      &daemon->genesis);
    }
    if (status == AL_OK) {
        status = al_node_storage_prepare_genesis(
            &daemon->storage, &daemon->genesis, &daemon->state_arena);
    }
    if (status == AL_OK) {
        al_state_snapshot snapshot;
        status = al_node_storage_state_snapshot(&daemon->storage, &snapshot);
        if (status == AL_OK) {
            al_state_store store =
                al_node_storage_state_store(&daemon->storage);
            status = al_state_open(
                &daemon->state, &store, &daemon->state_arena,
                daemon->genesis.fees.storage_deposit_per_byte,
                snapshot.height, &snapshot.root);
        }
    }
    if (status != AL_OK) goto fail;

    daemon->mempool_entries = (al_node_mempool_entry *)calloc(
        AL_DAEMON_MEMPOOL_ENTRIES, sizeof(*daemon->mempool_entries));
    daemon->mempool_bytes = (al_u8 *)malloc(AL_DAEMON_MEMPOOL_BYTES);
    daemon->round_mempool_entries = (al_node_mempool_entry *)calloc(
        AL_DAEMON_MEMPOOL_ENTRIES, sizeof(*daemon->round_mempool_entries));
    daemon->round_mempool_bytes = (al_u8 *)malloc(AL_DAEMON_MEMPOOL_BYTES);
    daemon->block_transactions = (al_transaction *)calloc(
        AL_BLOCK_MAX_TRANSACTIONS, sizeof(*daemon->block_transactions));
    daemon->receipts = (al_receipt *)calloc(AL_BLOCK_MAX_TRANSACTIONS,
                                            sizeof(*daemon->receipts));
    if (daemon->mempool_entries == NULL || daemon->mempool_bytes == NULL ||
        daemon->round_mempool_entries == NULL ||
        daemon->round_mempool_bytes == NULL ||
        daemon->block_transactions == NULL || daemon->receipts == NULL) {
        status = AL_ERR_OUT_OF_MEMORY;
        goto fail;
    }
    status = al_arena_init(&daemon->execution_arena, 1024u * 1024u);
    if (status != AL_OK) goto fail;

    al_node_buffers buffers;
    al_memzero(&buffers, sizeof(buffers));
    buffers.mempool_entries = daemon->mempool_entries;
    buffers.mempool_capacity = AL_DAEMON_MEMPOOL_ENTRIES;
    buffers.mempool_bytes = daemon->mempool_bytes;
    buffers.mempool_bytes_capacity = AL_DAEMON_MEMPOOL_BYTES;
    buffers.block_transactions = daemon->block_transactions;
    buffers.block_transaction_capacity = AL_BLOCK_MAX_TRANSACTIONS;
    buffers.receipts = daemon->receipts;
    buffers.receipt_capacity = AL_BLOCK_MAX_TRANSACTIONS;
    {
        const al_block_header *head = al_node_storage_head(&daemon->storage);
        status = al_node_open(&daemon->node, &daemon->genesis,
                              &daemon->state, &daemon->execution_arena,
                              buffers, head);
    }
    if (status != AL_OK) goto fail;

    status = load_or_create_proposer(daemon);
    if (status != AL_OK) goto fail;
    status = daemon_consensus_init(daemon);
    if (status != AL_OK) goto fail;
    if (daemon->consensus_ready && daemon->local_validator) {
        char signing_path[1024];
        status = path_join(daemon->config.data_dir, "signing.log",
                           signing_path, sizeof(signing_path));
        if (status == AL_OK) {
            status = al_signing_journal_open(
                &daemon->signing_journal, signing_path,
                daemon->genesis.chain_id, &daemon->proposer.pk);
        }
        if (status != AL_OK) goto fail;
        daemon->signing_journal_ready = AL_TRUE;
    }
    if (daemon->consensus_ready &&
        al_node_storage_finality_count(&daemon->storage) !=
            al_node_storage_block_count(&daemon->storage)) {
        status = AL_ERR_STATE_CORRUPT;
        goto fail;
    }

    if (daemon->config.enable_p2p) {
        al_p2p_config p2p_config;
        al_memzero(&p2p_config, sizeof(p2p_config));
        p2p_config.listen_port = daemon->config.p2p_port;
        p2p_config.protocol_version = AL_WIRE_PROTOCOL_VERSION;
        p2p_config.require_encryption =
            daemon->config.require_encrypted_transport;
        {
            al_hash256 genesis_hash;
            al_genesis_hash(&daemon->genesis, &genesis_hash);
            p2p_config.genesis = genesis_hash;
        }

        al_p2p_handlers handlers;
        al_memzero(&handlers, sizeof(handlers));
        handlers.userdata = daemon;
        handlers.on_transaction = daemon_on_transaction;
        handlers.on_block = daemon_on_block;
        handlers.on_consensus = daemon_on_consensus;
        if (daemon->consensus_ready) {
            handlers.on_finalized_block = daemon_on_finality;
            handlers.read_finalized_block = daemon_read_finalized_block;
        } else {
            handlers.read_block = daemon_read_block;
        }
        handlers.head_height = daemon_known_blocks;
        handlers.on_peer_up = daemon_peer_up;
        handlers.on_peer_down = daemon_peer_down;

        status = al_p2p_init(&daemon->p2p, &p2p_config, &handlers,
                             daemon->config.p2p_host,
                             daemon->config.p2p_port);
        if (status != AL_OK) goto fail;
        daemon->p2p_ready = AL_TRUE;
    }
    if (daemon->config.enable_rpc) {
        status = al_rpc_server_init(&daemon->rpc, daemon->config.rpc_host,
                                    daemon->config.rpc_port,
                                    daemon_rpc_handler, daemon);
        if (status != AL_OK) goto fail;
        if (daemon->config.rpc_token != NULL) {
            al_rpc_server_set_token(&daemon->rpc,
                                    (const al_u8 *)daemon->config.rpc_token,
                                    strlen(daemon->config.rpc_token));
        }
        daemon->rpc_ready = AL_TRUE;
    }

    {
        char message[192];
        (void)snprintf(
            message, sizeof(message),
            "node ready: chain %u, proposer %s, genesis %s",
            (unsigned)daemon->genesis.chain_id, daemon->proposer_hex,
            daemon->genesis_hex);
        DAEMON_LOG(daemon, message);
    }

    *out = daemon;
    return AL_OK;

fail:
    DAEMON_LOG(daemon, al_status_str(status));
    al_daemon_close(daemon);
    return status;
}

void al_daemon_close(al_daemon *daemon) {
    if (daemon == NULL) return;
    if (daemon->rpc_ready) al_rpc_server_close(&daemon->rpc);
    if (daemon->p2p_ready) al_p2p_close(&daemon->p2p);
    al_signing_journal_close(&daemon->signing_journal);
    al_node_storage_close(&daemon->storage);
    al_arena_destroy(&daemon->execution_arena);
    al_arena_destroy(&daemon->state_arena);
    daemon_free_scratch(daemon);
    al_signer_destroy(daemon->signer);
    free(daemon);
}

/* Block production: builds a block, signs a proposal, relays. */

#include "internal.h"

al_status daemon_produce_block(al_daemon *daemon) {
    if (daemon->consensus_ready) {
        if (daemon->pending_proposal || !daemon->local_validator) {
            return AL_ERR_NOT_FOUND;
        }
        const al_pubkey *expected = al_consensus_proposer(
            &daemon->committee, al_node_next_height(&daemon->node),
            daemon->consensus_round);
        if (expected == NULL ||
            daemon_pubkey_cmp(expected, &daemon->proposer.pk) != 0) {
            return AL_ERR_NOT_FOUND;
        }
    }
    if (daemon->block_scratch == NULL) {
        daemon->block_scratch_capacity = AL_WIRE_MAX_PAYLOAD;
        daemon->block_scratch =
            (al_u8 *)malloc(daemon->block_scratch_capacity);
        if (daemon->block_scratch == NULL) return AL_ERR_OUT_OF_MEMORY;
    }

    al_hash256 parent_hash = al_hash_zero();
    if (daemon->node.has_head) {
        al_block_header_hash(&daemon->node.head, &parent_hash);
    }

    al_node_proposal node_proposal;
    al_memzero(&node_proposal, sizeof(node_proposal));
    node_proposal.protocol_day =
        daemon->node.has_head ? daemon->node.head.protocol_day : 0u;
    node_proposal.proposer = daemon->proposer.pk;
    node_proposal.tip_flat = daemon->proposer_address;
    node_proposal.tip_weighted = daemon->proposer_address;
    node_proposal.tip_bonded = daemon->proposer_address;
    node_proposal.transaction_limit = daemon->node.mempool_count;

    al_size encoded_size = 0u;
    al_block_header produced_header;
    al_memzero(&produced_header, sizeof(produced_header));
    if (daemon->consensus_ready) {
        AL_TRY(daemon_round_checkpoint_take(daemon));
    }
    al_status status = al_node_produce_block(
        &daemon->node, &node_proposal,
        (al_bytes_mut){ daemon->block_scratch, daemon->block_scratch_capacity },
        &encoded_size);
    if (status != AL_OK) {
        if (daemon->consensus_ready) {
            (void)daemon_round_checkpoint_restore(daemon);
        }
        return status;
    }
    produced_header = daemon->node.head;

    al_bytes encoded = al_bytes_make(daemon->block_scratch, encoded_size);
    if (daemon->consensus_ready) {
        al_hash256 block_hash;
        al_block_header_hash(&produced_header, &block_hash);
        status = daemon_round_checkpoint_restore(daemon);
        if (status != AL_OK) {
            daemon->stop_requested = AL_TRUE;
            return status;
        }
        status = daemon_pending_begin(daemon, encoded, &block_hash,
                                      produced_header.height,
                                      daemon->consensus_round);
        if (status != AL_OK) {
            daemon->stop_requested = AL_TRUE;
            return status;
        }
        al_consensus_proposal consensus_proposal;
        al_memzero(&consensus_proposal, sizeof(consensus_proposal));
        consensus_proposal.version = AL_CONSENSUS_VERSION;
        consensus_proposal.chain_id = daemon->genesis.chain_id;
        consensus_proposal.height = produced_header.height;
        consensus_proposal.round = daemon->consensus_round;
        consensus_proposal.block_hash = block_hash;
        consensus_proposal.parent_hash = parent_hash;
        consensus_proposal.committee_hash = daemon->committee_hash;
        consensus_proposal.proposer = daemon->proposer.pk;
        al_hash256 signing_hash;
        al_consensus_proposal_hash(&consensus_proposal, &signing_hash);
        if (!daemon->signing_journal_ready) return AL_ERR_STATE_CORRUPT;
        status = al_signing_journal_record(
            &daemon->signing_journal, AL_SIGNING_PROPOSAL,
            consensus_proposal.height, consensus_proposal.round,
            &signing_hash);
        if (status != AL_OK) {
            daemon->stop_requested = AL_TRUE;
            return status;
        }
        status = al_consensus_proposal_sign(&consensus_proposal,
                                            &daemon->proposer.sk);
        if (status != AL_OK) return status;

        al_wire_proposal wire = { consensus_proposal, encoded };
        al_size payload_size = 0u;
        status = al_wire_proposal_encode(
            &wire, (al_bytes_mut){ NULL, 0u }, &payload_size);
        if (status != AL_ERR_BUFFER_TOO_SMALL) return status;
        al_u8 *payload = (al_u8 *)malloc(payload_size);
        if (payload == NULL) return AL_ERR_OUT_OF_MEMORY;
        al_size payload_written = 0u;
        status = al_wire_proposal_encode(
            &wire, (al_bytes_mut){ payload, payload_size }, &payload_written);
        if (status == AL_OK) {
            al_size relayed = al_p2p_relay_consensus(
                &daemon->p2p, AL_WIRE_PROPOSAL,
                al_bytes_make(payload, payload_written), NULL);
            (void)relayed;
            status = daemon_consensus_prevote(daemon);
        }
        free(payload);
        if (status != AL_OK) return status;
    } else if (daemon->config.data_dir != NULL) {
        status = al_node_storage_commit_block(&daemon->storage,
                                              &daemon->state, encoded);
        if (status != AL_OK) {
            DAEMON_LOG(daemon, "storage commit failed; stopping for recovery");
            daemon->stop_requested = AL_TRUE;
            return status;
        }
    }
    if (!daemon->consensus_ready) {
        al_size relayed = al_p2p_relay_block(&daemon->p2p, encoded, NULL);
        (void)relayed;
    }

    char message[160];
    (void)snprintf(message, sizeof(message),
                   "produced block %llu (%llu tx) root ",
                   (unsigned long long)produced_header.height,
                   (unsigned long long)node_proposal.transaction_limit);
    al_size used = (al_size)strlen(message);
    al_hash_to_hex(&produced_header.state_root,
                   message + used);
    DAEMON_LOG(daemon, message);
    for (al_size i = 0u; i < daemon->node.receipt_count &&
                         daemon->node.buffers.receipts != NULL;
         ++i) {
        const al_receipt *r = &daemon->node.buffers.receipts[i];
        (void)snprintf(message, sizeof(message), "  receipt[%llu] %s",
                       (unsigned long long)i,
                       r->status == AL_OK ? "ok" : al_status_str(r->status));
        DAEMON_LOG(daemon, message);
    }
    return AL_OK;
}

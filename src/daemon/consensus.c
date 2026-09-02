/* Consensus state machine: checkpoint, pending block, votes, finalization. */

#include "internal.h"

al_status daemon_round_checkpoint_take(al_daemon *daemon) {
    if (daemon->round_checkpoint_valid) return AL_ERR_ALREADY_EXISTS;
    daemon->round_state = al_state_snapshot_take(&daemon->state);
    daemon->round_head = daemon->node.head;
    daemon->round_stats = daemon->node.stats;
    daemon->round_mempool_count = daemon->node.mempool_count;
    daemon->round_mempool_bytes_used = daemon->node.mempool_bytes_used;
    daemon->round_receipt_count = daemon->node.receipt_count;
    daemon->round_had_head = daemon->node.has_head;
    memcpy(daemon->round_mempool_entries, daemon->mempool_entries,
           daemon->node.mempool_count * sizeof(*daemon->mempool_entries));
    memcpy(daemon->round_mempool_bytes, daemon->mempool_bytes,
           daemon->node.mempool_bytes_used);
    daemon->round_checkpoint_valid = AL_TRUE;
    return AL_OK;
}

al_status daemon_round_checkpoint_restore(al_daemon *daemon) {
    if (!daemon->round_checkpoint_valid) return AL_ERR_NOT_FOUND;
    AL_TRY(al_state_snapshot_restore(&daemon->state, daemon->round_state));
    daemon->node.head = daemon->round_head;
    daemon->node.stats = daemon->round_stats;
    daemon->node.mempool_count = daemon->round_mempool_count;
    daemon->node.mempool_bytes_used = daemon->round_mempool_bytes_used;
    daemon->node.receipt_count = daemon->round_receipt_count;
    daemon->node.has_head = daemon->round_had_head;
    memcpy(daemon->mempool_entries, daemon->round_mempool_entries,
           daemon->round_mempool_count * sizeof(*daemon->mempool_entries));
    memcpy(daemon->mempool_bytes, daemon->round_mempool_bytes,
           daemon->round_mempool_bytes_used);
    al_arena_reset(&daemon->execution_arena);
    daemon->round_checkpoint_valid = AL_FALSE;
    return AL_OK;
}

al_status daemon_pending_clear(al_daemon *daemon) {
    free(daemon->pending_block);
    daemon->pending_block = NULL;
    daemon->pending_block_size = 0u;
    daemon->pending_proposal = AL_FALSE;
    daemon->local_prevote_sent = AL_FALSE;
    daemon->local_precommit_sent = AL_FALSE;
    return AL_OK;
}

al_status daemon_pending_begin(al_daemon *daemon, al_bytes block,
                               const al_hash256 *block_hash,
                               al_height height,
                               al_u32 round) {
    if (daemon->pending_proposal || block.data == NULL || block.len == 0u ||
        block_hash == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    daemon->pending_block = (al_u8 *)malloc(block.len);
    if (daemon->pending_block == NULL) return AL_ERR_OUT_OF_MEMORY;
    memcpy(daemon->pending_block, block.data, block.len);
    daemon->pending_block_size = block.len;
    daemon->pending_block_hash = *block_hash;
    daemon->pending_height = height;
    daemon->consensus_round = round;
    daemon->pending_proposal = AL_TRUE;
    daemon->local_prevote_sent = AL_FALSE;
    daemon->local_precommit_sent = AL_FALSE;
    al_vote_set_init(&daemon->prevotes, daemon->genesis.chain_id,
                     height, round, AL_CONSENSUS_PREVOTE,
                     block_hash, &daemon->committee_hash);
    al_vote_set_init(&daemon->precommits, daemon->genesis.chain_id,
                     height, round, AL_CONSENSUS_PRECOMMIT,
                     block_hash, &daemon->committee_hash);
    return AL_OK;
}

al_status daemon_emit_vote(al_daemon *daemon,
                           al_consensus_phase phase) {
    if (!daemon->pending_proposal || !daemon->local_validator) {
        return AL_ERR_NOT_FOUND;
    }
    al_consensus_vote vote;
    al_memzero(&vote, sizeof(vote));
    vote.version = AL_CONSENSUS_VERSION;
    vote.chain_id = daemon->genesis.chain_id;
    vote.height = daemon->pending_height;
    vote.round = daemon->consensus_round;
    vote.phase = phase;
    vote.block_hash = daemon->pending_block_hash;
    vote.committee_hash = daemon->committee_hash;
    vote.voter = daemon->proposer.pk;
    al_hash256 signing_hash;
    al_consensus_vote_hash(&vote, &signing_hash);
    if (!daemon->signing_journal_ready) return AL_ERR_STATE_CORRUPT;
    al_signing_kind kind = phase == AL_CONSENSUS_PREVOTE
                               ? AL_SIGNING_PREVOTE
                               : AL_SIGNING_PRECOMMIT;
    al_status journal_status = al_signing_journal_record(
        &daemon->signing_journal, kind, vote.height, vote.round,
        &signing_hash);
    if (journal_status != AL_OK) {
        daemon->stop_requested = AL_TRUE;
        return journal_status;
    }
    AL_TRY(al_consensus_vote_sign(&vote, &daemon->proposer.sk));

    al_vote_set *set = phase == AL_CONSENSUS_PREVOTE
                           ? &daemon->prevotes
                           : &daemon->precommits;
    AL_TRY(al_vote_set_add(set, &vote, &daemon->committee));
    al_u8 encoded[AL_VOTE_ENCODED_SIZE];
    al_size written = 0u;
    AL_TRY(al_consensus_vote_encode(
        &vote, (al_bytes_mut){ encoded, sizeof(encoded) }, &written));
    al_size relayed = al_p2p_relay_consensus(
        &daemon->p2p, AL_WIRE_VOTE, al_bytes_make(encoded, written), NULL);
    (void)relayed;
    return AL_OK;
}

al_status daemon_finalize_pending(
    al_daemon *daemon, const al_finality_certificate *received) {
    if (!daemon->pending_proposal) return AL_ERR_NOT_FOUND;
    static al_finality_certificate local;
    const al_finality_certificate *certificate = received;
    if (certificate == NULL) {
        AL_TRY(al_vote_set_certificate(&daemon->precommits,
                                       &daemon->committee, &local));
        certificate = &local;
    }
    AL_TRY(al_finality_certificate_verify(certificate,
                                          &daemon->committee));
    if (certificate->chain_id != daemon->genesis.chain_id ||
        certificate->height != daemon->pending_height ||
        certificate->round != daemon->consensus_round ||
        !al_hash_eq(&certificate->block_hash,
                    &daemon->pending_block_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    al_bytes block = al_bytes_make(daemon->pending_block,
                                   daemon->pending_block_size);
    AL_TRY(al_node_accept_encoded_block(&daemon->node, block));
    al_size certificate_size = 0u;
    al_status status = al_finality_certificate_encode(
        certificate, (al_bytes_mut){ NULL, 0u }, &certificate_size);
    if (status != AL_ERR_BUFFER_TOO_SMALL) return status;
    al_u8 *encoded_certificate = (al_u8 *)malloc(certificate_size);
    if (encoded_certificate == NULL) return AL_ERR_OUT_OF_MEMORY;
    al_size certificate_written = 0u;
    status = al_finality_certificate_encode(
        certificate,
        (al_bytes_mut){ encoded_certificate, certificate_size },
        &certificate_written);
    if (status != AL_OK) {
        free(encoded_certificate);
        return status;
    }
    if (daemon->config.data_dir != NULL) {
        status = al_node_storage_commit_finalized_block(
            &daemon->storage, &daemon->state, block,
            al_bytes_make(encoded_certificate, certificate_written));
        if (status != AL_OK) {
            free(encoded_certificate);
            daemon->stop_requested = AL_TRUE;
            return status;
        }
    }

    if (received == NULL) {
        al_wire_finalized_block finalized = {
            al_bytes_make(encoded_certificate, certificate_written), block
        };
        al_size required = 0u;
        status = al_wire_finalized_block_encode(
            &finalized, (al_bytes_mut){ NULL, 0u }, &required);
        if (status != AL_ERR_BUFFER_TOO_SMALL) {
            free(encoded_certificate);
            return status;
        }
        al_u8 *encoded = (al_u8 *)malloc(required);
        if (encoded == NULL) {
            free(encoded_certificate);
            return AL_ERR_OUT_OF_MEMORY;
        }
        al_size written = 0u;
        status = al_wire_finalized_block_encode(
            &finalized, (al_bytes_mut){ encoded, required }, &written);
        if (status == AL_OK) {
            al_size relayed = al_p2p_relay_consensus(
                &daemon->p2p, AL_WIRE_FINALITY,
                al_bytes_make(encoded, written), NULL);
            (void)relayed;
        }
        free(encoded);
        if (status != AL_OK) {
            free(encoded_certificate);
            return status;
        }
    }
    free(encoded_certificate);

    char message[128];
    (void)snprintf(message, sizeof(message),
                   "finalized block %llu with %u votes",
                   (unsigned long long)certificate->height,
                   (unsigned)certificate->vote_count);
    DAEMON_LOG(daemon, message);
    AL_TRY(daemon_pending_clear(daemon));
    daemon->consensus_round = 0u;
    daemon->round_deadline_ms =
        al_net_now_ms() + (al_u64)daemon->config.round_timeout_ms;
    /* Re-select committee for the new height so both nodes converge. */
    AL_TRY(daemon_consensus_init(daemon));
    return AL_OK;
}

al_status daemon_consensus_advance(al_daemon *daemon) {
    if (!daemon->pending_proposal) return AL_ERR_NOT_FOUND;
    if (!daemon->local_precommit_sent && daemon->local_validator &&
        al_vote_set_has_quorum(&daemon->prevotes, &daemon->committee)) {
        daemon->local_precommit_sent = AL_TRUE;
        AL_TRY(daemon_emit_vote(daemon, AL_CONSENSUS_PRECOMMIT));
    }
    if (al_vote_set_has_quorum(&daemon->precommits, &daemon->committee)) {
        return daemon_finalize_pending(daemon, NULL);
    }
    return AL_OK;
}

al_status daemon_consensus_prevote(al_daemon *daemon) {
    if (!daemon->local_validator || daemon->local_prevote_sent) return AL_OK;
    daemon->local_prevote_sent = AL_TRUE;
    AL_TRY(daemon_emit_vote(daemon, AL_CONSENSUS_PREVOTE));
    return daemon_consensus_advance(daemon);
}

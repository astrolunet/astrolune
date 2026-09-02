/* Event loop and consensus wire handlers (proposal/vote/finality/evidence). */

#include "internal.h"

void daemon_dial_bootstraps(al_daemon *daemon) {
    if (!daemon->p2p_ready) return;
    for (al_size i = 0u; i < daemon->config.bootstrap_count; ++i) {
        char host[128];
        al_u16 port = 0u;
        if (!parse_endpoint(daemon->config.bootstrap[i], host, sizeof(host),
                            &port)) {
            continue;
        }
        al_status dial_status = al_p2p_dial(&daemon->p2p, host, port);
        (void)dial_status;
    }
}

al_status daemon_consensus_timeout(al_daemon *daemon, al_u64 now_ms) {
    if (!daemon->consensus_ready || now_ms < daemon->round_deadline_ms) {
        return AL_OK;
    }
    if (daemon->pending_proposal) {
        AL_TRY(daemon_pending_clear(daemon));
    }
    if (daemon->consensus_round == UINT32_MAX) {
        return AL_ERR_OUT_OF_RANGE;
    }
    ++daemon->consensus_round;
    daemon->round_deadline_ms =
        now_ms + (al_u64)daemon->config.round_timeout_ms;
    char message[96];
    (void)snprintf(message, sizeof(message), "entered consensus round %u",
                   (unsigned)daemon->consensus_round);
    DAEMON_LOG(daemon, message);
    return AL_OK;
}

al_bool al_daemon_run(al_daemon *daemon) {
    if (daemon == NULL) return AL_FALSE;

    al_u64 now_ms = al_net_now_ms();
    daemon->next_block_ms = now_ms + (al_u64)daemon->config.block_interval_ms;
    daemon->next_bootstrap_ms = now_ms + 5000u;
    daemon->round_deadline_ms =
        now_ms + (al_u64)daemon->config.round_timeout_ms;
    daemon_dial_bootstraps(daemon);

    while (!daemon->stop_requested &&
           (daemon->config.stop_flag == NULL ||
            *daemon->config.stop_flag == 0)) {
        if (daemon->p2p_ready) {
            al_p2p_poll(&daemon->p2p, 25u);
        }
        if (daemon->rpc_ready) {
            al_rpc_poll(&daemon->rpc, 0u);
        }

        now_ms = al_net_now_ms();
        al_status timeout_status = daemon_consensus_timeout(daemon, now_ms);
        if (timeout_status != AL_OK) {
            DAEMON_LOG(daemon, "consensus round transition failed");
            daemon->stop_requested = AL_TRUE;
            continue;
        }
        if (now_ms >= daemon->next_bootstrap_ms) {
            daemon_dial_bootstraps(daemon);
            daemon->next_bootstrap_ms = now_ms + 5000u;
        }

        if (daemon->config.block_interval_ms != 0u &&
            now_ms >= daemon->next_block_ms) {
            if (daemon->consensus_ready ||
                daemon->config.produce_empty_blocks ||
                daemon->node.mempool_count != 0u) {
                al_status produced =
                    daemon_produce_block(daemon);
                if (produced != AL_OK && produced != AL_ERR_NOT_FOUND) {
                    char message[128];
                    (void)snprintf(message, sizeof(message),
                                   "produce failed: %s",
                                   al_status_str(produced));
                    DAEMON_LOG(daemon, message);
                }
            }
            daemon->next_block_ms = now_ms +
                                    (al_u64)daemon->config.block_interval_ms;
        }
    }
    return AL_TRUE;
}

al_bool daemon_on_proposal(al_daemon *daemon, al_bytes encoded) {
    al_wire_proposal wire;
    if (al_wire_proposal_decode(encoded, &wire) != AL_OK ||
        wire.consensus.chain_id != daemon->genesis.chain_id ||
        al_consensus_proposal_verify(&wire.consensus,
                                     &daemon->committee) != AL_OK ||
        wire.consensus.height != al_node_next_height(&daemon->node) ||
        wire.consensus.round != daemon->consensus_round ||
        wire.block.len < AL_BLOCK_HEADER_ENCODED_SIZE) {
        return AL_FALSE;
    }

    al_block_header header;
    if (al_block_header_decode(
            al_bytes_slice(wire.block, 0u, AL_BLOCK_HEADER_ENCODED_SIZE),
            &header) != AL_OK) {
        return AL_FALSE;
    }
    al_hash256 block_hash;
    al_block_header_hash(&header, &block_hash);
    if (!al_hash_eq(&block_hash, &wire.consensus.block_hash) ||
        header.chain_id != wire.consensus.chain_id ||
        header.height != wire.consensus.height ||
        daemon_pubkey_cmp(&header.proposer, &wire.consensus.proposer) != 0) {
        return AL_FALSE;
    }
    al_hash256 expected_parent = al_hash_zero();
    if (daemon->node.has_head) {
        al_block_header_hash(&daemon->node.head, &expected_parent);
    }
    if (!al_hash_eq(&expected_parent, &wire.consensus.parent_hash) ||
        !al_hash_eq(&expected_parent, &header.parent_hash)) {
        return AL_FALSE;
    }
    if (daemon->pending_proposal) {
        if (al_hash_eq(&daemon->pending_block_hash, &block_hash)) {
            return AL_TRUE;
        }
        const al_pubkey *expected = al_consensus_proposer(
            &daemon->committee, wire.consensus.height, wire.consensus.round);
        if (expected == NULL ||
            daemon_pubkey_cmp(expected, &wire.consensus.proposer) != 0) {
            return AL_FALSE;
        }
        daemon_pending_clear(daemon);
    }
    if (daemon_round_checkpoint_take(daemon) != AL_OK) return AL_FALSE;
    al_status status = al_node_accept_encoded_block(&daemon->node, wire.block);
    al_status restore_status = daemon_round_checkpoint_restore(daemon);
    if (status != AL_OK || restore_status != AL_OK) {
        if (restore_status != AL_OK) daemon->stop_requested = AL_TRUE;
        return AL_FALSE;
    }
    if (daemon_pending_begin(daemon, wire.block, &block_hash,
                             wire.consensus.height,
                             wire.consensus.round) != AL_OK) {
        daemon->stop_requested = AL_TRUE;
        return AL_FALSE;
    }
    if (daemon_consensus_prevote(daemon) != AL_OK) {
        daemon->stop_requested = AL_TRUE;
        return AL_FALSE;
    }
    return AL_TRUE;
}

al_bool daemon_on_vote(al_daemon *daemon, al_bytes encoded) {
    al_consensus_vote vote;
    if (al_consensus_vote_decode(encoded, &vote) != AL_OK ||
        !daemon->pending_proposal ||
        vote.chain_id != daemon->genesis.chain_id ||
        vote.height != daemon->pending_height ||
        vote.round != daemon->consensus_round ||
        !al_hash_eq(&vote.block_hash, &daemon->pending_block_hash)) {
        return AL_FALSE;
    }
    al_vote_set *set = vote.phase == AL_CONSENSUS_PREVOTE
                           ? &daemon->prevotes
                           : &daemon->precommits;
    al_status status = al_vote_set_add(set, &vote, &daemon->committee);
    if (status == AL_ERR_ALREADY_EXISTS) return AL_TRUE;
    if (status != AL_OK) return AL_FALSE;
    status = daemon_consensus_advance(daemon);
    if (status != AL_OK) {
        daemon->stop_requested = AL_TRUE;
        return AL_FALSE;
    }
    return AL_TRUE;
}

al_bool daemon_on_finality(void *userdata, al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    al_wire_finalized_block finalized;
    if (al_wire_finalized_block_decode(encoded, &finalized) != AL_OK ||
        finalized.block.len < AL_BLOCK_HEADER_ENCODED_SIZE) {
        return AL_FALSE;
    }
    static al_finality_certificate certificate;
    if (al_finality_certificate_decode(finalized.certificate,
                                       &certificate) != AL_OK ||
        al_finality_certificate_verify(&certificate,
                                       &daemon->committee) != AL_OK) {
        return AL_FALSE;
    }
    al_block_header header;
    if (al_block_header_decode(
            al_bytes_slice(finalized.block, 0u,
                           AL_BLOCK_HEADER_ENCODED_SIZE),
            &header) != AL_OK) {
        return AL_FALSE;
    }
    al_hash256 block_hash;
    al_block_header_hash(&header, &block_hash);
    const al_pubkey *expected = al_consensus_proposer(
        &daemon->committee, certificate.height, certificate.round);
    if (certificate.chain_id != daemon->genesis.chain_id ||
        header.chain_id != certificate.chain_id ||
        header.height != certificate.height ||
        !al_hash_eq(&block_hash, &certificate.block_hash) ||
        expected == NULL ||
        daemon_pubkey_cmp(&header.proposer, expected) != 0) {
        return AL_FALSE;
    }

    al_height next_height = al_node_next_height(&daemon->node);
    if (certificate.height < next_height) {
        al_size stored_size = 0u;
        al_status status = al_node_storage_read_block(
            &daemon->storage, certificate.height,
            (al_bytes_mut){ NULL, 0u }, &stored_size);
        if (status != AL_ERR_BUFFER_TOO_SMALL ||
            stored_size != finalized.block.len) {
            return AL_FALSE;
        }
        al_u8 *stored = (al_u8 *)malloc(stored_size);
        if (stored == NULL) return AL_FALSE;
        status = al_node_storage_read_block(
            &daemon->storage, certificate.height,
            (al_bytes_mut){ stored, stored_size }, &stored_size);
        al_bool matches = status == AL_OK &&
                          al_bytes_eq(al_bytes_make(stored, stored_size),
                                      finalized.block);
        free(stored);
        return matches;
    }
    if (certificate.height != next_height) return AL_FALSE;

    if (daemon->pending_proposal) {
        if (!al_bytes_eq(al_bytes_make(daemon->pending_block,
                                       daemon->pending_block_size),
                         finalized.block)) {
            return AL_FALSE;
        }
    } else {
        if (daemon_round_checkpoint_take(daemon) != AL_OK) return AL_FALSE;
        al_status validation =
            al_node_accept_encoded_block(&daemon->node, finalized.block);
        al_status restore_status = daemon_round_checkpoint_restore(daemon);
        if (validation != AL_OK || restore_status != AL_OK) {
            if (restore_status != AL_OK) daemon->stop_requested = AL_TRUE;
            return AL_FALSE;
        }
        if (daemon_pending_begin(daemon, finalized.block, &block_hash,
                                 certificate.height,
                                 certificate.round) != AL_OK) {
            daemon->stop_requested = AL_TRUE;
            return AL_FALSE;
        }
    }
    al_status status = daemon_finalize_pending(daemon, &certificate);
    if (status != AL_OK) {
        daemon->stop_requested = AL_TRUE;
        return AL_FALSE;
    }
    return AL_TRUE;
}

al_bool daemon_on_evidence(al_daemon *daemon, al_bytes encoded) {
    al_wire_evidence wire;
    if (al_wire_evidence_decode(encoded, &wire) != AL_OK) {
        return AL_FALSE;
    }
    if (wire.evidence.chain_id != daemon->genesis.chain_id) {
        return AL_FALSE;
    }
    if (al_evidence_verify(&wire.evidence, &daemon->committee) != AL_OK) {
        return AL_FALSE;
    }
    for (al_size i = 0u; i < daemon->committee.size; ++i) {
        if (daemon_pubkey_cmp(&daemon->committee.members[i],
                              &wire.evidence.vote1.voter) == 0) {
            for (al_size j = 0u; j < daemon->committee.size; ++j) {
                if (daemon_pubkey_cmp(&daemon->validator_records[j].identity,
                                      &wire.evidence.vote1.voter) == 0) {
                    al_potb_record *record = &daemon->validator_records[j];
                    al_u32 now_day = 0u;
                    if (daemon->node.has_head) {
                        now_day = daemon->node.head.protocol_day;
                    }
                    (void)al_evidence_process(&daemon->genesis.potb, record,
                                              &wire.evidence, now_day);
                    char message[160];
                    char pk_hex[AL_PUBKEY_SIZE * 2u + 1u];
                    (void)al_hex_encode(al_bytes_make(wire.evidence.vote1.voter.bytes,
                                                AL_PUBKEY_SIZE),
                                  pk_hex, sizeof(pk_hex));
                    int evidence_msg_len = snprintf(message, sizeof(message),
                                   "evidence processed: double-sign by %s at height %llu",
                                   pk_hex,
                                   (unsigned long long)wire.evidence.height);
                    (void)evidence_msg_len;
                    DAEMON_LOG(daemon, message);
                    break;
                }
            }
            break;
        }
    }
    return AL_TRUE;
}

al_bool daemon_on_consensus(void *userdata, al_wire_type type,
                           al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    if (!daemon->consensus_ready) return AL_FALSE;
    switch (type) {
    case AL_WIRE_PROPOSAL:
        return daemon_on_proposal(daemon, encoded);
    case AL_WIRE_VOTE:
        return daemon_on_vote(daemon, encoded);
    case AL_WIRE_EVIDENCE:
        return daemon_on_evidence(daemon, encoded);
    case AL_WIRE_HELLO:
    case AL_WIRE_PING:
    case AL_WIRE_PONG:
    case AL_WIRE_TX:
    case AL_WIRE_BLOCK:
    case AL_WIRE_GET_BLOCKS:
    case AL_WIRE_BLOCKS:
    case AL_WIRE_FINALITY:
    case AL_WIRE_TYPE_SENTINEL:
    default:
        return AL_FALSE;
    }
}

void al_daemon_request_stop(al_daemon *daemon) {
    if (daemon != NULL) daemon->stop_requested = AL_TRUE;
}

const char *al_daemon_proposer_address(const al_daemon *daemon) {
    return daemon != NULL ? daemon->proposer_hex : NULL;
}

/* Node daemon implementation. See daemon.h for the design notes. */

#include "daemon.h"

#include "internal/common.h"
#include "json.h"
#include "node.h"
#include "p2p.h"
#include "random.h"
#include "server.h"
#include "signing_journal.h"
#include "storage.h"
#include "finality.h"

#include "astrolune/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
/* ------------------------------------------------------------------ */

struct al_daemon {
    al_daemon_config config;

    /* Chain inputs and durable store. */
    al_genesis            genesis;
    al_genesis_allocation allocations[AL_GENESIS_MAX_ALLOCATIONS];

    al_arena        state_arena;
    al_node_storage storage;
    al_state        state;

    /* Execution scratch owned here because the runtime requires caller
     * buffers for both the mempool and block decoding. */
    al_arena               execution_arena;
    al_node_mempool_entry *mempool_entries;
    al_u8                 *mempool_bytes;
    al_transaction        *block_transactions;
    al_receipt            *receipts;

    al_node node;

    /* PoTB finality runtime. */
    al_potb_record        validator_records[AL_DAEMON_MAX_VALIDATORS];
    const al_potb_record *validator_index[AL_DAEMON_MAX_VALIDATORS];
    al_potb_network_stats validator_stats;
    al_potb_committee     committee;
    al_hash256            committee_hash;
    al_vote_set           prevotes;
    al_vote_set           precommits;
    al_u8                *pending_block;
    al_size               pending_block_size;
    al_hash256            pending_block_hash;
    al_height             pending_height;
    al_u32                consensus_round;
    al_bool               consensus_ready;
    al_bool               local_validator;
    al_bool               pending_proposal;
    al_bool               local_prevote_sent;
    al_bool               local_precommit_sent;
    al_signing_journal    signing_journal;
    al_bool               signing_journal_ready;
    al_state_snapshot     round_state;
    al_block_header       round_head;
    al_node_stats         round_stats;
    al_node_mempool_entry *round_mempool_entries;
    al_u8                 *round_mempool_bytes;
    al_size               round_mempool_count;
    al_size               round_mempool_bytes_used;
    al_size               round_receipt_count;
    al_bool               round_had_head;
    al_bool               round_checkpoint_valid;
    al_u64                round_deadline_ms;

    /* Identity used to sign produced blocks. */
    al_keypair proposer;
    al_address proposer_address;
    char       proposer_hex[AL_ADDRESS_HEX_SIZE];
    char       genesis_hex[AL_HASH_HEX_SIZE];

    /* Services. */
    al_p2p        p2p;
    al_bool       p2p_ready;
    al_rpc_server rpc;
    al_bool       rpc_ready;

    /* Reusable encoding scratch for produced blocks. */
    al_u8  *block_scratch;
    al_size block_scratch_capacity;

    al_u64  next_block_ms;
    al_u64  next_bootstrap_ms;
    al_bool stop_requested;
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static void daemon_log(const al_daemon *daemon, const char *message) {
    AL_LOG_INFO("daemon", "[%s] %s", daemon->config.data_dir, message);
}

#define DAEMON_LOG(daemon, text) daemon_log((daemon), (text))

static int daemon_pubkey_cmp(const al_pubkey *a, const al_pubkey *b) {
    return memcmp(a->bytes, b->bytes, AL_PUBKEY_SIZE);
}

static al_status daemon_parse_validator_key(const char *text,
                                            al_pubkey *out) {
    if (text == NULL || out == NULL) return AL_ERR_INVALID_ARG;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2u;
    if (strlen(text) != AL_PUBKEY_SIZE * 2u) return AL_ERR_MALFORMED;
    al_size written = 0u;
    AL_TRY(al_hex_decode(text, out->bytes, AL_PUBKEY_SIZE, &written));
    return written == AL_PUBKEY_SIZE ? AL_OK : AL_ERR_MALFORMED;
}

static al_status daemon_consensus_init(al_daemon *daemon) {
    if (daemon->config.validator_count == 0u) return AL_OK;
    if (daemon->config.validator_count > AL_DAEMON_MAX_VALIDATORS) {
        return AL_ERR_OUT_OF_RANGE;
    }

    al_size count = daemon->config.validator_count;
    for (al_size i = 0u; i < count; ++i) {
        al_pubkey identity;
        AL_TRY(daemon_parse_validator_key(daemon->config.validators[i],
                                          &identity));
        daemon->validator_records[i] = al_potb_record_init(&identity);
        al_potb_record *record = &daemon->validator_records[i];
        record->uptime_days = 3650u;
        record->responses_total = 1000u;
        record->responses_correct = 1000u;
        record->votes_expected = 1000u;
        record->votes_cast = 1000u;
        record->inbound_attestations = 128u;
        record->cluster_size = 1u;
        record->tdi = AL_FIXED_ONE;
        record->challenges_issued = 128u;
        record->challenges_passed = 128u;
        record->asn = (al_u32)(i + 1u);
        record->asn_peer_count = 1u;
    }

    /* Validator configuration order is not consensus-visible. */
    for (al_size i = 1u; i < count; ++i) {
        al_potb_record value = daemon->validator_records[i];
        al_size j = i;
        while (j > 0u &&
               daemon_pubkey_cmp(&value.identity,
                                 &daemon->validator_records[j - 1u].identity) <
                   0) {
            daemon->validator_records[j] = daemon->validator_records[j - 1u];
            --j;
        }
        daemon->validator_records[j] = value;
    }
    for (al_size i = 0u; i < count; ++i) {
        if (i != 0u &&
            daemon_pubkey_cmp(&daemon->validator_records[i - 1u].identity,
                              &daemon->validator_records[i].identity) == 0) {
            return AL_ERR_ALREADY_EXISTS;
        }
        daemon->validator_index[i] = &daemon->validator_records[i];
    }

    al_memzero(&daemon->validator_stats, sizeof(daemon->validator_stats));
    daemon->validator_stats.node_count = (al_u32)count;
    for (al_size i = 0u; i < count; ++i) {
        daemon->validator_stats.total_weight = al_fixed_add(
            daemon->validator_stats.total_weight,
            al_potb_weight_total(&daemon->genesis.potb,
                                 daemon->validator_index[i],
                                 &daemon->validator_stats, 0u));
    }

    al_hash256 seed;
    al_genesis_hash(&daemon->genesis, &seed);
    AL_TRY(al_potb_committee_select(
        &daemon->genesis.potb, daemon->validator_index, count,
        &daemon->validator_stats, &seed, 0u,
        0u, &daemon->execution_arena, &daemon->committee));
    if (daemon->committee.size != count) return AL_ERR_CONSENSUS_VIOLATION;
    al_consensus_committee_hash(&daemon->committee,
                                &daemon->committee_hash);
    daemon->local_validator = al_potb_committee_contains(
        &daemon->committee, &daemon->proposer.pk);
    daemon->consensus_ready = AL_TRUE;
    {
        const al_pubkey *leader = al_consensus_proposer(
            &daemon->committee, al_node_next_height(&daemon->node), 0u);
        char leader_hex[AL_PUBKEY_SIZE * 2u + 1u];
        if (leader != NULL) {
            AL_TRY(al_hex_encode(
                al_bytes_make(leader->bytes, AL_PUBKEY_SIZE), leader_hex,
                sizeof(leader_hex)));
        } else {
            leader_hex[0] = '\0';
        }
        char message[192];
        (void)snprintf(message, sizeof(message),
                       "consensus ready: %u validators, local %s, leader %s",
                       (unsigned)daemon->committee.size,
                       daemon->local_validator ? "validator" : "relay",
                       leader_hex);
        DAEMON_LOG(daemon, message);
    }
    return AL_OK;
}

static al_status read_whole_file(const char *path, al_u8 **data_out,
                                 al_size *size_out, al_size max_size) {
    if (path == NULL || data_out == NULL || size_out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    *data_out = NULL;
    *size_out = 0u;

    FILE *file = fopen(path, "rb");
    if (file == NULL) return AL_ERR_NOT_FOUND;
    if (fseek(file, 0, SEEK_END) != 0) {
        (void)fclose(file);
        return AL_ERR_IO;
    }
    long length = ftell(file);
    if (length <= 0 || (al_size)length > max_size ||
        fseek(file, 0, SEEK_SET) != 0) {
        (void)fclose(file);
        return length > 0 ? AL_ERR_OUT_OF_RANGE : AL_ERR_IO;
    }

    al_u8 *data = (al_u8 *)malloc((al_size)length);
    if (data == NULL) {
        (void)fclose(file);
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_size read = fread(data, 1u, (al_size)length, file);
    int close_status = fclose(file);
    if (read != (al_size)length || close_status != 0) {
        free(data);
        return AL_ERR_IO;
    }
    *data_out = data;
    *size_out = read;
    return AL_OK;
}

static al_status path_join(const char *directory, const char *name, char *out,
                           al_size cap) {
    int written = snprintf(out, cap, "%s/%s", directory, name);
    if (written <= 0 || (al_size)written >= cap) return AL_ERR_OUT_OF_RANGE;
    return AL_OK;
}

/* Parse "host:port". Host names here are IPv4 literals or resolvable names;
 * bare IPv6 is not accepted by design of the endpoint grammar. */
static al_bool parse_endpoint(const char *endpoint, char *host, al_size cap,
                              al_u16 *port) {
    const char *separator = strrchr(endpoint, ':');
    if (separator == NULL || separator == endpoint) return AL_FALSE;
    long value = strtol(separator + 1u, NULL, 10);
    if (value <= 0 || value > 65535) return AL_FALSE;
    al_size host_len = (al_size)(separator - endpoint);
    if (host_len >= cap) return AL_FALSE;
    memcpy(host, endpoint, host_len);
    host[host_len] = '\0';
    *port = (al_u16)value;
    return AL_TRUE;
}

/* ------------------------------------------------------------------ */
/* Proposer identity                                                   */
/* ------------------------------------------------------------------ */

#define PROPOSER_KEY_FILE  "proposer.key"
#define PROPOSER_SEED_SIZE 32u

static al_status load_or_create_proposer(al_daemon *daemon) {
    /* An explicit seed (devnets, tests) wins over anything on disk. */
    if (daemon->config.proposer_seed != NULL) {
        al_u8 seed[PROPOSER_SEED_SIZE];
        al_status status = al_hex_decode(daemon->config.proposer_seed, seed,
                                         sizeof(seed), NULL);
        if (status != AL_OK) return AL_ERR_MALFORMED;
        AL_TRY(al_keypair_from_seed(seed, &daemon->proposer));
        al_secure_zero(seed, sizeof(seed));
        al_address_from_pubkey(&daemon->proposer.pk,
                               &daemon->proposer_address);
        al_address_to_hex(&daemon->proposer_address, daemon->proposer_hex);
        return AL_OK;
    }

    char path[512];
    AL_TRY(path_join(daemon->config.data_dir, PROPOSER_KEY_FILE, path,
                     sizeof(path)));

    al_u8 *contents = NULL;
    al_size size = 0u;
    al_status status = read_whole_file(path, &contents, &size, 256u);
    if (status == AL_OK) {
        al_u8 seed[PROPOSER_SEED_SIZE];
        status =
            al_hex_decode((const char *)contents, seed, sizeof(seed), NULL);
        free(contents);
        if (status != AL_OK) return AL_ERR_MALFORMED;
        AL_TRY(al_keypair_from_seed(seed, &daemon->proposer));
        al_secure_zero(seed, sizeof(seed));
    } else if (status == AL_ERR_NOT_FOUND) {
        /* First start in this directory: mint an identity from platform
         * entropy and persist it before anything touches the network. The
         * file is the only record of this proposer's address. */
        al_u8 seed[PROPOSER_SEED_SIZE];
        if (!os_random_bytes(seed, sizeof(seed))) return AL_ERR_IO;
        AL_TRY(al_keypair_from_seed(seed, &daemon->proposer));
        al_secure_zero(seed, sizeof(seed));

        char text[PROPOSER_SEED_SIZE * 2u + 1u];
        AL_TRY(al_hex_encode(
            al_bytes_make(daemon->proposer.sk.bytes, PROPOSER_SEED_SIZE),
            text, sizeof(text)));
        FILE *file = fopen(path, "wb");
        if (file == NULL) return AL_ERR_IO;
        al_size written = fwrite(text, 1u, sizeof(text) - 1u, file);
        int close_status = fclose(file);
        if (written != sizeof(text) - 1u || close_status != 0) {
            return AL_ERR_IO;
        }
    } else {
        return status;
    }

    al_address_from_pubkey(&daemon->proposer.pk, &daemon->proposer_address);
    al_address_to_hex(&daemon->proposer_address, daemon->proposer_hex);
    return AL_OK;
}

/* ------------------------------------------------------------------ */
/* P2P handlers                                                        */
/* ------------------------------------------------------------------ */

static al_status daemon_consensus_prevote(al_daemon *daemon);
static al_status daemon_consensus_advance(al_daemon *daemon);

static al_status daemon_round_checkpoint_take(al_daemon *daemon) {
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

static al_status daemon_round_checkpoint_restore(al_daemon *daemon) {
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

static al_status daemon_pending_clear(al_daemon *daemon) {
    free(daemon->pending_block);
    daemon->pending_block = NULL;
    daemon->pending_block_size = 0u;
    daemon->pending_proposal = AL_FALSE;
    daemon->local_prevote_sent = AL_FALSE;
    daemon->local_precommit_sent = AL_FALSE;
    return AL_OK;
}

static al_status daemon_pending_begin(al_daemon *daemon, al_bytes block,
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

static al_status daemon_emit_vote(al_daemon *daemon,
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

static al_status daemon_finalize_pending(
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
    return AL_OK;
}

static al_status daemon_consensus_advance(al_daemon *daemon) {
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

static al_status daemon_consensus_prevote(al_daemon *daemon) {
    if (!daemon->local_validator || daemon->local_prevote_sent) return AL_OK;
    daemon->local_prevote_sent = AL_TRUE;
    AL_TRY(daemon_emit_vote(daemon, AL_CONSENSUS_PREVOTE));
    return daemon_consensus_advance(daemon);
}

static al_bool daemon_on_transaction(void *userdata, al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    al_hash256 hash;
    return al_node_submit_transaction(&daemon->node, encoded, &hash) == AL_OK
               ? AL_TRUE
               : AL_FALSE;
}

static al_bool daemon_on_block(void *userdata, al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    if (daemon->consensus_ready) {
        return AL_FALSE;
    }
    al_status status =
        al_node_accept_encoded_block(&daemon->node, encoded);
    if (status != AL_OK) {
        /* Duplicates and stale races are routine gossip noise; anything else
         * is worth one line so operators can see desync immediately. */
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

static al_status daemon_read_block(void *userdata, al_height height,
                                   al_bytes_mut buffer, al_size *written) {
    al_daemon *daemon = (al_daemon *)userdata;
    return al_node_storage_read_block(&daemon->storage, height, buffer,
                                      written);
}

static al_status daemon_read_finalized_block(
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

/* Height semantics on the wire are "how many canonical blocks do you know";
 * an empty chain reports zero. */
static al_height daemon_known_blocks(void *userdata) {
    al_daemon *daemon = (al_daemon *)userdata;
    return daemon->node.has_head ? daemon->node.head.height + 1u : 0u;
}

static void daemon_peer_up(void *userdata, const al_p2p_peer *peer) {
    al_daemon *daemon = (al_daemon *)userdata;
    char message[160];
    (void)snprintf(message, sizeof(message), "peer up: %s (%llu known)",
                   peer->endpoint, (unsigned long long)peer->height);
    DAEMON_LOG(daemon, message);
}

static void daemon_peer_down(void *userdata, const char *endpoint) {
    al_daemon *daemon = (al_daemon *)userdata;
    char message[160];
    (void)snprintf(message, sizeof(message), "peer down: %s", endpoint);
    DAEMON_LOG(daemon, message);
}

/* ------------------------------------------------------------------ */
/* Block production                                                    */
/* ------------------------------------------------------------------ */

static al_status daemon_produce_block(al_daemon *daemon) {
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

/* ------------------------------------------------------------------ */
/* RPC surface                                                         */
/* ------------------------------------------------------------------ */

/* JSON-RPC parameters live under "params"; flat requests are accepted too so
 * quick manual curl calls stay ergonomic. */
static const al_json_value *rpc_params(const al_json_value *request) {
    const al_json_value *params = al_json_get(request, "params");
    return params != NULL && params->kind == AL_JSON_OBJECT ? params
                                                            : request;
}

static al_status json_parse_address(const al_json_value *request,
                                    const char *key, al_address *out) {
    const char *text = al_json_as_string(al_json_get(request, key));
    if (text == NULL) return AL_ERR_INVALID_ARG;
    /* User-facing form first; raw hex (0x-prefixed or bare) still works. */
    if (strncmp(text, "al1", 3) == 0) {
        return al_address_from_bech32(text, out);
    }
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2u;
    return al_hex_decode(text, out->bytes, sizeof(out->bytes), NULL);
}

/* Addresses in responses use the bech32 user-facing form. */
static al_status json_write_address_field(al_json_writer *body,
                                          const char *field,
                                          const al_address *address) {
    char text[AL_ADDRESS_TEXT_SIZE];
    al_status status = al_address_to_bech32(address, text, sizeof(text));
    if (status != AL_OK) return status;
    al_json_writer_raw(body, ",\"");
    al_json_writer_raw(body, field);
    al_json_writer_raw(body, "\":\"");
    al_json_writer_raw(body, text);
    al_json_writer_raw(body, "\"");
    return AL_OK;
}

/* Amounts arrive as JSON numbers or decimal strings; wallets prefer the
 * string form to dodge 53-bit JavaScript integers. */
static al_status json_parse_amount(const al_json_value *request,
                                   const char *key, al_amount *out) {
    const al_json_value *value = al_json_get(request, key);
    if (value == NULL) return AL_ERR_INVALID_ARG;
    if (al_json_as_u64(value, out)) return AL_OK;
    const char *text = al_json_as_string(value);
    if (text == NULL || *text == '\0') return AL_ERR_INVALID_ARG;
    al_u64 parsed = 0u;
    for (const char *p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return AL_ERR_INVALID_ARG;
        al_u64 digit = (al_u64)(*p - '0');
        if (parsed > (UINT64_MAX - digit) / 10u) return AL_ERR_OUT_OF_RANGE;
        parsed = parsed * 10u + digit;
    }
    *out = parsed;
    return AL_OK;
}

static void json_write_account(al_json_writer *writer,
                               const al_account *account) {
    char text[AL_ADDRESS_TEXT_SIZE];
    al_json_writer_raw(writer, "{\"address\":");
    if (al_address_to_bech32(&account->address, text, sizeof(text)) == AL_OK) {
        al_json_writer_string(writer, text);
    } else {
        al_json_writer_hex(writer,
                           al_bytes_make(account->address.bytes,
                                         AL_ADDRESS_SIZE));
    }
    al_json_writer_raw(writer, ",\"balance\":");
    al_json_writer_u64(writer, account->balance);
    al_json_writer_raw(writer, ",\"nonce\":");
    al_json_writer_u64(writer, account->nonce);
    al_json_writer_raw(writer, ",\"code_hash\":");
    al_json_writer_hex(writer,
                       al_bytes_make(account->code_hash.bytes, AL_HASH_SIZE));
    al_json_writer_raw(writer, ",\"storage_root\":");
    al_json_writer_hex(writer, al_bytes_make(account->storage_root.bytes,
                                             AL_HASH_SIZE));
    al_json_writer_raw(writer, ",\"storage_bytes\":");
    al_json_writer_u64(writer, account->storage_bytes);
    al_json_writer_raw(writer, ",\"storage_deposit\":");
    al_json_writer_u64(writer, account->storage_deposit);
    al_json_writer_raw(writer, "}");
}

/*
 * Build, sign and admit one transfer from the proposer identity. This is the
 * convenience path wallets exercise; raw submissions bypass it entirely.
 */
static al_status rpc_transfer(al_daemon *daemon, const al_json_value *request,
                              al_json_writer *body) {
    al_address recipient;
    AL_TRY(json_parse_address(request, "to", &recipient));
    al_amount amount = 0u;
    AL_TRY(json_parse_amount(request, "amount", &amount));

    al_account account;
    al_status step =
        al_state_get(&daemon->state, &daemon->proposer_address, &account);
    al_nonce nonce = 0u;
    if (step == AL_OK) {
        nonce = account.nonce;
    } else if (step != AL_ERR_NOT_FOUND) {
        return step;
    }

    al_transaction transaction;
    al_memzero(&transaction, sizeof(transaction));
    transaction.version = AL_TX_VERSION;
    transaction.chain_id = daemon->genesis.chain_id;
    transaction.expiry_height = daemon_known_blocks(daemon) + 128u;
    transaction.sender = daemon->proposer.pk;
    transaction.nonce = nonce;
    transaction.resource_limit.compute = 1000000u;
    transaction.resource_limit.memory = 1000000u;
    transaction.resource_limit.storage = 1000000u;
    transaction.resource_limit.bandwidth = 1000000u;
    transaction.max_base_price.compute = 10000u;
    transaction.max_base_price.memory = 10000u;
    transaction.max_base_price.storage = 10000u;
    transaction.max_base_price.bandwidth = 10000u;
    transaction.tip = 0u;
    transaction.type = AL_TX_TRANSFER;
    transaction.body.transfer.recipient = recipient;
    transaction.body.transfer.amount = amount;
    AL_TRY(al_tx_sign(&transaction, &daemon->proposer.sk));

    al_u8 encoded[1024];
    al_size encoded_size = 0u;
    AL_TRY(al_tx_encode(&transaction,
                        (al_bytes_mut){ encoded, sizeof(encoded) },
                        &encoded_size));
    al_hash256 hash;
    step = al_node_submit_transaction(&daemon->node,
                                      al_bytes_make(encoded, encoded_size),
                                      &hash);
    if (step != AL_OK) {
        /* One operator-visible line: why the wallet's transfer bounced. */
        AL_LOG_WARN("rpc", "transfer rejected: %s", al_status_str(step));
        return step;
    }

    al_json_writer_raw(body, "{\"hash\":");
    al_json_writer_hex(body, al_bytes_make(hash.bytes, AL_HASH_SIZE));
    al_json_writer_raw(body, ",\"nonce\":");
    al_json_writer_u64(body, nonce);
    al_json_writer_raw(body, "}");
    return AL_OK;
}

static void write_hash_string(al_json_writer *body, const char *hex) {
    /* hex strings are already encoded; emit them as JSON strings. */
    al_json_writer_raw(body, "\"0x");
    al_json_writer_raw(body, hex);
    al_json_writer_raw(body, "\"");
}

/*
 * Read-only contract call: snapshot, apply, restore. Lets wallets and the
 * smoke suite query contract state between blocks without paying fees or
 * waiting for a block.
 */
static al_status rpc_dry_run_call(al_daemon *daemon,
                                  const al_json_value *params,
                                  al_json_writer *body) {
    const char *to_text = al_json_as_string(al_json_get(params, "to"));
    if (to_text == NULL) {
        return al_rpc_respond_error(body, -32602, "missing to");
    }
    al_address contract;
    if (json_parse_address(params, "to", &contract) != AL_OK) {
        return al_rpc_respond_error(body, -32602, "invalid address");
    }
    const al_json_value *entry_value = al_json_get(params, "entrypoint");
    uint64_t entrypoint = 0u;
    if (entry_value != NULL && !al_json_as_u64(entry_value, &entrypoint)) {
        return al_rpc_respond_error(body, -32602, "invalid entrypoint");
    }

    /* Arguments: JSON array of u64 numbers, little-endian packed. */
    static al_u8 calldata[512];
    al_size calldata_len = 0u;
    const al_json_value *args = al_json_get(params, "args");
    if (args != NULL && args->kind != AL_JSON_NULL) {
        if (args->kind != AL_JSON_ARRAY ||
            args->count > AL_COUNTOF(calldata) / 8u) {
            return al_rpc_respond_error(body, -32602, "invalid args");
        }
        for (al_size i = 0u; i < args->count; ++i) {
            uint64_t value = 0u;
            if (!al_json_as_u64(args->children[i], &value)) {
                return al_rpc_respond_error(body, -32602,
                                            "args must be u64 numbers");
            }
            al_store_le64(calldata + i * 8u, value);
            calldata_len += 8u;
        }
    }

    al_account account;
    al_status status =
        al_state_get(&daemon->state, &daemon->proposer_address, &account);
    al_nonce nonce = 0u;
    if (status == AL_OK) {
        nonce = account.nonce;
    } else if (status != AL_ERR_NOT_FOUND) {
        return status;
    }

    const al_block_header *head =
        daemon->node.has_head ? &daemon->node.head : NULL;

    al_transaction tx;
    al_memzero(&tx, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = daemon->genesis.chain_id;
    tx.expiry_height = daemon_known_blocks(daemon) + 128u;
    tx.sender = daemon->proposer.pk;
    tx.nonce = nonce;
    tx.resource_limit.compute = 1000000u;
    tx.resource_limit.memory = 1000000u;
    tx.resource_limit.storage = 1000000u;
    tx.resource_limit.bandwidth = 1000000u;
    tx.max_base_price.compute = 10000u;
    tx.max_base_price.memory = 10000u;
    tx.max_base_price.storage = 10000u;
    tx.max_base_price.bandwidth = 10000u;
    tx.type = AL_TX_CALL;
    tx.body.call.contract = contract;
    tx.body.call.entrypoint = (al_u32)entrypoint;
    tx.body.call.calldata = al_bytes_make(calldata, calldata_len);
    AL_TRY(al_tx_sign(&tx, &daemon->proposer.sk));

    al_tx_context context;
    al_memzero(&context, sizeof(context));
    context.chain_id = daemon->genesis.chain_id;
    context.block_height = head ? head->height + 1u : 0u;
    context.protocol_day = head ? head->protocol_day : 0u;
    context.base_prices =
        head ? head->base_prices : daemon->genesis.fees.initial_base_price;
    context.tip_flat = daemon->proposer_address;
    context.tip_weighted = daemon->proposer_address;
    context.tip_bonded = daemon->proposer_address;
    context.vm.stack_limit = daemon->genesis.vm_stack_limit;
    context.vm.memory_limit = daemon->genesis.vm_memory_limit;
    context.vm.call_depth_limit = daemon->genesis.vm_call_depth_limit;
    context.vm.resource_limit = daemon->genesis.fees.block_limit;
    context.vm.schedule = &daemon->genesis.schedule;
    context.arena = &daemon->execution_arena;

    al_arena_mark scratch = al_arena_save(&daemon->execution_arena);
    al_state_snapshot rollback = al_state_snapshot_take(&daemon->state);
    al_receipt receipt;
    status = al_tx_apply(&tx, &daemon->state, &context, &receipt);
    /* Return data lives in the scratch arena; copy it out before any
     * restore reclaims the region. */
    char data_hex[129] = { 0 };
    if (receipt.return_data.len != 0u) {
        al_size shown = receipt.return_data.len < 64u
                            ? receipt.return_data.len
                            : 64u;
        AL_TRY(al_hex_encode(
            al_bytes_slice(receipt.return_data, 0u, shown), data_hex,
            sizeof(data_hex)));
    }

    al_status restore_status =
        al_state_snapshot_restore(&daemon->state, rollback);
    al_arena_restore(&daemon->execution_arena, scratch);
    if (restore_status != AL_OK) return restore_status;

    if (status != AL_OK && status != AL_ERR_REVERTED) {
        return status;
    }

    al_json_writer_raw(body, "{\"status\":");
    if (receipt.status == AL_OK) {
        al_json_writer_raw(body, "\"ok\"");
    } else if (receipt.status == AL_ERR_REVERTED) {
        al_json_writer_raw(body, "\"reverted\"");
    } else {
        al_json_writer_string(body, al_status_str(receipt.status));
    }
    al_json_writer_raw(body, ",\"data\":\"0x");
    al_json_writer_raw(body, data_hex);
    al_json_writer_raw(body, "\",\"events\":");
    al_json_writer_u64(body, receipt.event_count);
    al_json_writer_raw(body, "}");
    return AL_OK;
}

static al_status daemon_rpc_handler(void *userdata,
                                    const al_json_value *request,
                                    al_json_writer *body) {
    al_daemon *daemon = (al_daemon *)userdata;
    const char *method = al_json_as_string(al_json_get(request, "method"));
    if (method == NULL) {
        return al_rpc_respond_error(body, -32600, "missing method");
    }

    if (strcmp(method, "get_info") == 0) {
        al_hash256 head_hash = al_hash_zero();
        if (daemon->node.has_head) {
            al_block_header_hash(&daemon->node.head, &head_hash);
        }
        char head_hex[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&head_hash, head_hex);

        al_json_writer_raw(body,
                           "{\"name\":\"astrolune\",\"version\":");
        al_json_writer_string(body, al_version_string());
        al_json_writer_raw(body, ",\"chain_id\":");
        al_json_writer_u64(body, daemon->genesis.chain_id);
        al_json_writer_raw(body, ",\"height\":");
        if (daemon->node.has_head) {
            al_json_writer_u64(body, daemon->node.head.height);
        } else {
            al_json_writer_raw(body, "null");
        }
        al_json_writer_raw(body, ",\"head\":");
        write_hash_string(body, head_hex);
        al_json_writer_raw(body, ",\"state_root\":");
        al_json_writer_hex(body,
                           al_bytes_make(daemon->state.root.bytes,
                                         AL_HASH_SIZE));
        al_json_writer_raw(body, ",\"genesis\":");
        write_hash_string(body, daemon->genesis_hex);
        al_json_writer_raw(body, ",\"proposer\":");
        write_hash_string(body, daemon->proposer_hex);
        (void)json_write_address_field(body, "proposer_bech32",
                                       &daemon->proposer_address);
        al_json_writer_raw(body, ",\"crypto_backend\":");
        al_json_writer_string(body, al_crypto_backend_name());
        al_json_writer_raw(body, ",\"crypto_secure\":");
        al_json_writer_raw(body, al_crypto_is_secure() ? "true" : "false");
        al_json_writer_raw(body, ",\"peers\":");
        al_json_writer_u64(body, al_p2p_ready_peers(&daemon->p2p));
        al_json_writer_raw(body, ",\"mempool\":");
        al_json_writer_u64(body, daemon->node.mempool_count);
        al_json_writer_raw(body, "}");
        return AL_OK;
    }

    if (strcmp(method, "get_account") == 0) {
        al_address address;
        al_status status = json_parse_address(rpc_params(request), "address", &address);
        if (status != AL_OK) {
            return al_rpc_respond_error(body, -32602, "invalid address");
        }
        al_account account;
        status = al_state_get(&daemon->state, &address, &account);
        if (status == AL_ERR_NOT_FOUND) {
            al_json_writer_raw(body, "null");
            return AL_OK;
        }
        if (status != AL_OK) return status;
        json_write_account(body, &account);
        return AL_OK;
    }

    if (strcmp(method, "send_raw_transaction") == 0) {
        const char *text =
            al_json_as_string(al_json_get(rpc_params(request), "data"));
        if (text == NULL) {
            return al_rpc_respond_error(body, -32602, "missing data");
        }
        if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2u;

        al_size decoded_capacity = strlen(text) / 2u + 1u;
        al_u8 *decoded = (al_u8 *)malloc(decoded_capacity);
        if (decoded == NULL) return AL_ERR_OUT_OF_MEMORY;
        al_size decoded_len = 0u;
        al_status status =
            al_hex_decode(text, decoded, decoded_capacity, &decoded_len);
        if (status == AL_OK) {
            al_hash256 hash;
            status = al_node_submit_transaction(
                &daemon->node, al_bytes_make(decoded, decoded_len), &hash);
            if (status == AL_OK) {
                al_json_writer_raw(body, "{\"hash\":");
                al_json_writer_hex(body,
                                   al_bytes_make(hash.bytes, AL_HASH_SIZE));
                al_json_writer_raw(body, "}");
            }
        }
        free(decoded);

        if (status == AL_ERR_MALFORMED || status == AL_ERR_NOT_CANONICAL ||
            status == AL_ERR_TRUNCATED || status == AL_ERR_TRAILING_BYTES ||
            status == AL_ERR_BAD_SIGNATURE || status == AL_ERR_INVALID_ARG) {
            return al_rpc_respond_error(body, -32602,
                                        "malformed transaction");
        }
        if (status != AL_OK) {
            /* Surface the core's reason: operators need to know whether a
             * submission bounced on funds, nonce or shape. */
            return al_rpc_respond_error(body, -32050,
                                        al_status_str(status));
        }
        return AL_OK;
    }

    if (strcmp(method, "dry_run_call") == 0) {
        return rpc_dry_run_call(daemon, rpc_params(request), body);
    }

    if (strcmp(method, "transfer") == 0) {
        if (!daemon->config.enable_unsafe_rpc) {
            return al_rpc_respond_error(body, -32601, "method not found");
        }
        return rpc_transfer(daemon, rpc_params(request), body);
    }

    if (strcmp(method, "get_mempool") == 0) {
        al_json_writer_raw(body, "[");
        for (al_size i = 0u; i < daemon->node.mempool_count; ++i) {
            const al_node_mempool_entry *entry =
                al_node_mempool_at(&daemon->node, i);
            if (entry == NULL) break;
            if (i != 0u) al_json_writer_raw(body, ",");
            al_json_writer_raw(body, "{\"hash\":");
            al_json_writer_hex(body,
                               al_bytes_make(entry->hash.bytes, AL_HASH_SIZE));
            al_json_writer_raw(body, ",\"nonce\":");
            al_json_writer_u64(body, entry->transaction.nonce);
            al_json_writer_raw(body, ",\"tip\":");
            al_json_writer_u64(body, entry->transaction.tip);
            al_json_writer_raw(body, "}");
        }
        al_json_writer_raw(body, "]");
        return AL_OK;
    }

    if (strcmp(method, "get_block") == 0) {
        const al_json_value *params = rpc_params(request);
        al_i64 height = -1;
        const char *hash_hex = NULL;

        /* Accept either {"height": N} or {"hash": "0x..."} */
        const al_json_value *hv = al_json_get(params, "height");
        if (hv && hv->kind == AL_JSON_U64) {
            height = (al_i64)hv->u64_value;
        }
        const al_json_value *hh = al_json_get(params, "hash");
        if (hh && hh->kind == AL_JSON_STRING) {
            hash_hex = hh->string;
        }

        al_u64 block_count = al_node_storage_block_count(&daemon->storage);
        if (height < 0) {
            /* Default: head block */
            if (!daemon->node.has_head) {
                al_json_writer_raw(body, "null");
                return AL_OK;
            }
            height = (al_i64)daemon->node.head.height;
        }
        if ((al_u64)height >= block_count) {
            al_json_writer_raw(body, "null");
            return AL_OK;
        }

        /* Read the encoded block from storage. */
        al_size encoded_cap = 0u;
        al_status rs = al_node_storage_read_block(
            &daemon->storage, (al_height)height, (al_bytes_mut){NULL, 0},
            &encoded_cap);
        if (rs != AL_ERR_BUFFER_TOO_SMALL) {
            al_json_writer_raw(body, "null");
            return AL_OK;
        }
        al_u8 *encoded = (al_u8 *)malloc(encoded_cap);
        if (encoded == NULL) return AL_ERR_OUT_OF_MEMORY;
        rs = al_node_storage_read_block(
            &daemon->storage, (al_height)height,
            (al_bytes_mut){ encoded, encoded_cap }, &encoded_cap);
        if (rs != AL_OK) {
            free(encoded);
            al_json_writer_raw(body, "null");
            return AL_OK;
        }

        /* Decode the block. */
        al_block block = {0};
        rs = al_block_decode(al_bytes_make(encoded, encoded_cap),
                             daemon->block_transactions,
                             AL_BLOCK_MAX_TRANSACTIONS, &block);
        if (rs != AL_OK) {
            free(encoded);
            al_json_writer_raw(body, "null");
            return AL_OK;
        }

        /* Hash the block header for the "hash" field. */
        al_hash256 block_hash;
        al_block_header_hash(&block.header, &block_hash);
        char hash_buf[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&block_hash, hash_buf);
        if (hash_hex != NULL && strcmp(hash_hex, hash_buf) != 0) {
            free(encoded);
            al_json_writer_raw(body, "null");
            return AL_OK;
        }

        /* Hash the parent. */
        char parent_buf[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&block.header.parent_hash, parent_buf);

        /* Write the block JSON. */
        al_json_writer_raw(body, "{\"hash\":");
        write_hash_string(body, hash_buf);
        al_json_writer_raw(body, ",\"height\":");
        al_json_writer_u64(body, block.header.height);
        al_json_writer_raw(body, ",\"parent\":");
        write_hash_string(body, parent_buf);
        al_json_writer_raw(body, ",\"proposer\":");
        al_json_writer_hex(body,
                           al_bytes_make(block.header.proposer.bytes,
                                         AL_PUBKEY_SIZE));
        al_json_writer_raw(body, ",\"transaction_count\":");
        al_json_writer_u64(body, block.transaction_count);
        al_json_writer_raw(body, ",\"transactions\":[");
        for (al_size i = 0u; i < block.transaction_count; ++i) {
            al_hash256 tx_hash;
            al_tx_hash(&block.transactions[i], &tx_hash);
            char tx_buf[AL_HASH_HEX_SIZE];
            al_hash_to_hex(&tx_hash, tx_buf);
            if (i != 0u) al_json_writer_raw(body, ",");
            write_hash_string(body, tx_buf);
        }
        al_json_writer_raw(body, "]}");
        free(encoded);
        return AL_OK;
    }

    if (strcmp(method, "get_transaction") == 0) {
        const al_json_value *params = rpc_params(request);
        const al_json_value *hh = al_json_get(params, "hash");
        if (!hh || hh->kind != AL_JSON_STRING) {
            return al_rpc_respond_error(body, -32602, "missing hash");
        }
        /* Search mempool first. */
        for (al_size i = 0u; i < daemon->node.mempool_count; ++i) {
            const al_node_mempool_entry *entry =
                al_node_mempool_at(&daemon->node, i);
            if (entry == NULL) break;
            char entry_hex[AL_HASH_HEX_SIZE];
            al_hash_to_hex(&entry->hash, entry_hex);
            if (strcmp(entry_hex, hh->string) == 0) {
                al_json_writer_raw(body, "{\"status\":\"pending\",\"hash\":");
                al_json_writer_hex(body,
                                   al_bytes_make(entry->hash.bytes,
                                                 AL_HASH_SIZE));
                al_json_writer_raw(body, ",\"nonce\":");
                al_json_writer_u64(body, entry->transaction.nonce);
                al_json_writer_raw(body, ",\"tip\":");
                al_json_writer_u64(body, entry->transaction.tip);
                al_json_writer_raw(body, "}");
                return AL_OK;
            }
        }
        /* Not found in mempool or historical index. */
        al_json_writer_raw(body, "null");
        return AL_OK;
    }

    if (strcmp(method, "get_receipt") == 0) {
        const al_json_value *params = rpc_params(request);
        const al_json_value *hh = al_json_get(params, "hash");
        if (!hh || hh->kind != AL_JSON_STRING) {
            return al_rpc_respond_error(body, -32602, "missing hash");
        }
        /* Search receipts from the last block. */
        al_size receipt_count = 0u;
        const al_receipt *receipts = al_node_receipts(&daemon->node,
                                                      &receipt_count);
        for (al_size i = 0u; i < receipt_count; ++i) {
            char rx_hex[AL_HASH_HEX_SIZE];
            al_hash_to_hex(&receipts[i].transaction_hash, rx_hex);
            if (strcmp(rx_hex, hh->string) == 0) {
                const al_receipt *r = &receipts[i];
                al_json_writer_raw(body, "{\"transaction_hash\":");
                al_json_writer_hex(body,
                                   al_bytes_make(r->transaction_hash.bytes,
                                                 AL_HASH_SIZE));
                al_json_writer_raw(body, ",\"status\":");
                al_json_writer_u64(body, (al_u64)r->status);
                al_json_writer_raw(body, ",\"compute\":");
                al_json_writer_u64(body, r->resources.compute);
                al_json_writer_raw(body, ",\"memory\":");
                al_json_writer_u64(body, r->resources.memory);
                al_json_writer_raw(body, ",\"storage\":");
                al_json_writer_u64(body, r->resources.storage);
                al_json_writer_raw(body, ",\"bandwidth\":");
                al_json_writer_u64(body, r->resources.bandwidth);
                al_json_writer_raw(body, ",\"base_fee_burned\":");
                al_json_writer_u64(body, r->base_fee_burned);
                al_json_writer_raw(body, ",\"tip_paid\":");
                al_json_writer_u64(body, r->tip_paid);
                al_json_writer_raw(body, ",\"events\":");
                al_json_writer_u64(body, r->event_count);
                al_json_writer_raw(body, "}");
                return AL_OK;
            }
        }
        al_json_writer_raw(body, "null");
        return AL_OK;
    }

    if (strcmp(method, "get_peers") == 0) {
        al_json_writer_raw(body, "[");
        al_size emitted = 0u;
        for (al_size i = 0u; i < daemon->p2p.peer_count; ++i) {
            const al_p2p_peer *peer = &daemon->p2p.peers[i];
            if (peer->state != AL_P2P_READY) continue;
            if (emitted != 0u) al_json_writer_raw(body, ",");
            emitted++;
            al_json_writer_raw(body, "{\"endpoint\":");
            al_json_writer_string(body, peer->endpoint);
            al_json_writer_raw(body, ",\"inbound\":");
            al_json_writer_raw(body, peer->inbound ? "true" : "false");
            al_json_writer_raw(body, ",\"known_blocks\":");
            al_json_writer_u64(body, peer->height);
            al_json_writer_raw(body, "}");
        }
        al_json_writer_raw(body, "]");
        return AL_OK;
    }

    if (strcmp(method, "stop") == 0) {
        if (!daemon->config.enable_unsafe_rpc) {
            return al_rpc_respond_error(body, -32601, "method not found");
        }
        daemon->stop_requested = AL_TRUE;
        al_json_writer_raw(body, "{\"stopping\":true}");
        return AL_OK;
    }

    return al_rpc_respond_error(body, -32601, "method not found");
}

/* ------------------------------------------------------------------ */
/* Event loop                                                          */
/* ------------------------------------------------------------------ */

static void daemon_dial_bootstraps(al_daemon *daemon) {
    if (!daemon->p2p_ready) return;
    for (al_size i = 0u; i < daemon->config.bootstrap_count; ++i) {
        char host[128];
        al_u16 port = 0u;
        if (!parse_endpoint(daemon->config.bootstrap[i], host, sizeof(host),
                            &port)) {
            continue;
        }
        /* Already-connected endpoints fail harmlessly inside dial. */
        al_status dial_status = al_p2p_dial(&daemon->p2p, host, port);
        (void)dial_status;
    }
}

static al_status daemon_consensus_timeout(al_daemon *daemon, al_u64 now_ms) {
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

static al_bool daemon_on_proposal(al_daemon *daemon, al_bytes encoded) {
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
        return al_hash_eq(&daemon->pending_block_hash, &block_hash);
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

static al_bool daemon_on_vote(al_daemon *daemon, al_bytes encoded) {
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

static al_bool daemon_on_finality(void *userdata, al_bytes encoded) {
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
        expected == NULL || daemon_pubkey_cmp(&header.proposer, expected) != 0) {
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

static al_bool daemon_on_consensus(void *userdata, al_wire_type type,
                                   al_bytes encoded) {
    al_daemon *daemon = (al_daemon *)userdata;
    if (!daemon->consensus_ready) return AL_FALSE;
    switch (type) {
    case AL_WIRE_PROPOSAL:
        return daemon_on_proposal(daemon, encoded);
    case AL_WIRE_VOTE:
        return daemon_on_vote(daemon, encoded);
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

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void daemon_free_scratch(al_daemon *daemon) {
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
    /* RPC exposes privileged local controls and has no authentication layer;
     * never turn a missing host into an all-interface listener. */
    if (daemon->config.enable_rpc && daemon->config.rpc_host == NULL) {
        daemon->config.rpc_host = "127.0.0.1";
    }

    /* Genesis file. */
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

    /* Durable store plus live state at the last committed root. */
    status = al_arena_init(&daemon->state_arena, 1024u * 1024u);
    if (status == AL_OK) {
        status = al_node_storage_open(&daemon->storage,
                                      daemon->config.data_dir,
                                      &daemon->genesis);
    }
    if (status == AL_OK) {
        /* Rebuild the prefunded tree on first start with a new directory. */
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

    /* Scratch buffers. */
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

    /* Services. */
    if (daemon->config.enable_p2p) {
        al_p2p_config p2p_config;
        al_memzero(&p2p_config, sizeof(p2p_config));
        p2p_config.listen_port = daemon->config.p2p_port;
        p2p_config.protocol_version = AL_WIRE_PROTOCOL_VERSION;
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
    free(daemon);
}

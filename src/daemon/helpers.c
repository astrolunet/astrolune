/* Node daemon implementation. See daemon.h for the design notes. */

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

void daemon_log(const al_daemon *daemon, const char *message) {
    AL_LOG_INFO("daemon", "[%s] %s", daemon->config.data_dir, message);
}

int daemon_pubkey_cmp(const al_pubkey *a, const al_pubkey *b) {
    return memcmp(a->bytes, b->bytes, AL_PUBKEY_SIZE);
}

al_status daemon_parse_validator_key(const char *text, al_pubkey *out) {
    if (text == NULL || out == NULL) return AL_ERR_INVALID_ARG;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2u;
    if (strlen(text) != AL_PUBKEY_SIZE * 2u) return AL_ERR_MALFORMED;
    al_size written = 0u;
    AL_TRY(al_hex_decode(text, out->bytes, AL_PUBKEY_SIZE, &written));
    return written == AL_PUBKEY_SIZE ? AL_OK : AL_ERR_MALFORMED;
}

al_status daemon_consensus_init(al_daemon *daemon) {
    al_height height = al_node_next_height(&daemon->node);
    al_size count = 0u;

    if (height == 0u) {
        /* Genesis: use static config validators. */
        if (daemon->config.validator_count == 0u) return AL_OK;
        if (daemon->config.validator_count > AL_DAEMON_MAX_VALIDATORS) {
            return AL_ERR_OUT_OF_RANGE;
        }

        count = daemon->config.validator_count;
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
    } else {
        /* After genesis: load validators from on-chain state. */
        al_state_txn txn;
        AL_TRY(al_state_txn_begin(daemon->node.state, &txn));
        
        al_u32 protocol_day = 0u;
        if (daemon->node.has_head) {
            protocol_day = daemon->node.head.protocol_day;
        }
        AL_TRY(al_validator_set_load(
            &txn, &daemon->genesis.potb,
            daemon->validator_records, AL_DAEMON_MAX_VALIDATORS,
            daemon->validator_index, &count,
            protocol_day));
        
        al_state_txn_rollback(&txn);
        
        if (count == 0u) {
            if (daemon->config.validator_count == 0u) return AL_OK;
            if (daemon->config.validator_count > AL_DAEMON_MAX_VALIDATORS) {
                return AL_ERR_OUT_OF_RANGE;
            }
            count = daemon->config.validator_count;
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
            for (al_size i = 0u; i < count; ++i) {
                daemon->validator_index[i] = &daemon->validator_records[i];
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
        }
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
        &daemon->validator_stats, &seed, height,
        0u, &daemon->execution_arena, &daemon->committee));
    if (daemon->committee.size == 0u) return AL_ERR_CONSENSUS_VIOLATION;
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

al_status read_whole_file(const char *path, al_u8 **data_out,
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

al_status path_join(const char *directory, const char *name, char *out,
                    al_size cap) {
    int written = snprintf(out, cap, "%s/%s", directory, name);
    if (written <= 0 || (al_size)written >= cap) return AL_ERR_OUT_OF_RANGE;
    return AL_OK;
}

al_bool parse_endpoint(const char *endpoint, char *host, al_size cap,
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

al_status load_or_create_proposer(al_daemon *daemon) {
    /* An explicit seed (devnets, tests) wins over anything on disk. */
    if (daemon->config.proposer_seed != NULL) {
        al_status status = al_signer_new_from_hex(daemon->config.proposer_seed,
                                                  &daemon->signer);
        if (status != AL_OK) return status;
        AL_TRY(al_signer_pubkey(daemon->signer, &daemon->proposer.pk));
        al_u8 seed[PROPOSER_SEED_SIZE];
        status = al_hex_decode(daemon->config.proposer_seed, seed,
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

    /* If passphrase is provided, use encrypted-at-rest mode. */
    if (daemon->config.proposer_passphrase != NULL) {
        al_u8 *contents = NULL;
        al_size size = 0u;
        al_status status = read_whole_file(path, &contents, &size, 256u);
        
        if (status == AL_OK) {
            if (size != AL_SIGNER_ENCRYPTED_SIZE) {
                free(contents);
                return AL_ERR_MALFORMED;
            }
            al_u8 seed[PROPOSER_SEED_SIZE];
            status = al_signer_decrypt_seed(contents,
                                            daemon->config.proposer_passphrase,
                                            seed);
            free(contents);
            if (status != AL_OK) return status;
            
            char seed_hex[PROPOSER_SEED_SIZE * 2u + 1u];
            status = al_hex_encode(al_bytes_make(seed, sizeof(seed)),
                                   seed_hex, sizeof(seed_hex));
            if (status == AL_OK) {
                status = al_signer_new_from_hex(seed_hex, &daemon->signer);
            }
            al_secure_zero(seed, sizeof(seed));
            if (status != AL_OK) return status;
            AL_TRY(al_signer_pubkey(daemon->signer, &daemon->proposer.pk));
        } else if (status == AL_ERR_NOT_FOUND) {
            al_u8 seed[PROPOSER_SEED_SIZE];
            if (!os_random_bytes(seed, sizeof(seed))) return AL_ERR_IO;
            
            al_u8 encrypted[AL_SIGNER_ENCRYPTED_SIZE];
            status = al_signer_encrypt_seed(seed,
                                            daemon->config.proposer_passphrase,
                                            encrypted);
            if (status != AL_OK) {
                al_secure_zero(seed, sizeof(seed));
                return status;
            }
            
            FILE *file = fopen(path, "wb");
            if (file == NULL) {
                al_secure_zero(seed, sizeof(seed));
                return AL_ERR_IO;
            }
            al_size written = fwrite(encrypted, 1u, sizeof(encrypted), file);
            int close_status = fclose(file);
            if (written != sizeof(encrypted) || close_status != 0) {
                al_secure_zero(seed, sizeof(seed));
                return AL_ERR_IO;
            }
            
            char hex[65];
            status = al_hex_encode(al_bytes_make(seed, PROPOSER_SEED_SIZE),
                                   hex, sizeof(hex));
            al_secure_zero(seed, sizeof(seed));
            if (status != AL_OK) return status;
            
            status = al_signer_new_from_hex(hex, &daemon->signer);
            if (status != AL_OK) return status;
            AL_TRY(al_signer_pubkey(daemon->signer, &daemon->proposer.pk));
        } else {
            return status;
        }
    } else {
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
            AL_TRY(al_signer_new_from_keypair(&daemon->proposer, &daemon->signer));
        } else if (status == AL_ERR_NOT_FOUND) {
            al_u8 seed[PROPOSER_SEED_SIZE];
            if (!os_random_bytes(seed, sizeof(seed))) return AL_ERR_IO;
            AL_TRY(al_keypair_from_seed(seed, &daemon->proposer));
            
            char hex[65];
            AL_TRY(al_hex_encode(
                al_bytes_make(daemon->proposer.sk.bytes, PROPOSER_SEED_SIZE),
                hex, sizeof(hex)));
            AL_TRY(al_signer_new_from_hex(hex, &daemon->signer));
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
    }

    al_address_from_pubkey(&daemon->proposer.pk, &daemon->proposer_address);
    al_address_to_hex(&daemon->proposer_address, daemon->proposer_hex);
    return AL_OK;
}

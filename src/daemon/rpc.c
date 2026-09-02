/* JSON-RPC surface: all RPC method handlers. */

#include "internal.h"

/* ------------------------------------------------------------------ */
/* RPC helpers                                                         */
/* ------------------------------------------------------------------ */

static const al_json_value *rpc_params(const al_json_value *request) {
    const al_json_value *params = al_json_get(request, "params");
    return params != NULL && params->kind == AL_JSON_OBJECT ? params
                                                            : request;
}

static al_status json_parse_address(const al_json_value *request,
                                    const char *key, al_address *out) {
    const char *text = al_json_as_string(al_json_get(request, key));
    if (text == NULL) return AL_ERR_INVALID_ARG;
    if (strncmp(text, "al1", 3) == 0) {
        return al_address_from_bech32(text, out);
    }
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2u;
    return al_hex_decode(text, out->bytes, sizeof(out->bytes), NULL);
}

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
        AL_LOG_WARN("rpc", "transfer rejected: %s", al_status_str(step));
        return step;
    }
    if (daemon->p2p_ready) {
        (void)al_p2p_relay_transaction(&daemon->p2p,
                                       al_bytes_make(encoded, encoded_size),
                                       NULL);
    }

    al_json_writer_raw(body, "{\"hash\":");
    al_json_writer_hex(body, al_bytes_make(hash.bytes, AL_HASH_SIZE));
    al_json_writer_raw(body, ",\"nonce\":");
    al_json_writer_u64(body, nonce);
    al_json_writer_raw(body, "}");
    return AL_OK;
}

static void write_hash_string(al_json_writer *body, const char *hex) {
    al_json_writer_raw(body, "\"0x");
    al_json_writer_raw(body, hex);
    al_json_writer_raw(body, "\"");
}

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
    context.potb_params = &daemon->genesis.potb;

    al_arena_mark scratch = al_arena_save(&daemon->execution_arena);
    al_state_snapshot rollback = al_state_snapshot_take(&daemon->state);
    al_receipt receipt;
    status = al_tx_apply(&tx, &daemon->state, &context, &receipt);
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

/* ------------------------------------------------------------------ */
/* Main RPC dispatch                                                   */
/* ------------------------------------------------------------------ */

al_status daemon_rpc_handler(void *userdata,
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
        al_status status = json_parse_address(rpc_params(request), "address",
                                              &address);
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
                if (daemon->p2p_ready) {
                    (void)al_p2p_relay_transaction(
                        &daemon->p2p,
                        al_bytes_make(decoded, decoded_len), NULL);
                }
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

        al_block block = {0};
        rs = al_block_decode(al_bytes_make(encoded, encoded_cap),
                             daemon->block_transactions,
                             AL_BLOCK_MAX_TRANSACTIONS, &block);
        if (rs != AL_OK) {
            free(encoded);
            al_json_writer_raw(body, "null");
            return AL_OK;
        }

        al_hash256 block_hash;
        al_block_header_hash(&block.header, &block_hash);
        char hash_buf[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&block_hash, hash_buf);
        if (hash_hex != NULL && strcmp(hash_hex, hash_buf) != 0) {
            free(encoded);
            al_json_writer_raw(body, "null");
            return AL_OK;
        }

        char parent_buf[AL_HASH_HEX_SIZE];
        al_hash_to_hex(&block.header.parent_hash, parent_buf);

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
        al_json_writer_raw(body, "null");
        return AL_OK;
    }

    if (strcmp(method, "get_receipt") == 0) {
        const al_json_value *params = rpc_params(request);
        const al_json_value *hh = al_json_get(params, "hash");
        if (!hh || hh->kind != AL_JSON_STRING) {
            return al_rpc_respond_error(body, -32602, "missing hash");
        }
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

    if (strcmp(method, "submit_evidence") == 0) {
        if (!daemon->config.enable_unsafe_rpc) {
            return al_rpc_respond_error(body, -32601, "method not found");
        }
        const al_json_value *params = rpc_params(request);
        const char *hex_data = al_json_as_string(al_json_get(params, "data"));
        if (hex_data == NULL) {
            return al_rpc_respond_error(body, -32602, "missing data");
        }
        if (hex_data[0] == '0' && (hex_data[1] == 'x' || hex_data[1] == 'X')) {
            hex_data += 2u;
        }
        al_size decoded_cap = strlen(hex_data) / 2u + 1u;
        al_u8 *decoded = (al_u8 *)malloc(decoded_cap);
        if (decoded == NULL) return AL_ERR_OUT_OF_MEMORY;
        al_size decoded_len = 0u;
        al_status estatus = al_hex_decode(hex_data, decoded, decoded_cap,
                                          &decoded_len);
        if (estatus != AL_OK) {
            free(decoded);
            return al_rpc_respond_error(body, -32602, "invalid hex");
        }
        al_evidence evidence;
        estatus = al_evidence_decode(al_bytes_make(decoded, decoded_len),
                                    &evidence);
        if (estatus != AL_OK) {
            free(decoded);
            return al_rpc_respond_error(body, -32602, "invalid evidence");
        }
        if (evidence.chain_id != daemon->genesis.chain_id) {
            free(decoded);
            return al_rpc_respond_error(body, -32602, "chain_id mismatch");
        }
        al_account account;
        estatus = al_state_get(&daemon->state, &daemon->proposer_address,
                               &account);
        al_nonce nonce = 0u;
        if (estatus == AL_OK) {
            nonce = account.nonce;
        } else if (estatus != AL_ERR_NOT_FOUND) {
            free(decoded);
            return estatus;
        }
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
        tx.tip = 0u;
        tx.type = AL_TX_POTB;
        tx.body.potb.target = evidence.vote1.voter;
        tx.body.potb.amount = 0u;
        tx.body.potb.operation = AL_POTB_OFFENCE_EVIDENCE;
        tx.body.potb.data = al_bytes_make(decoded, decoded_len);
        al_status sign_status = al_tx_sign(&tx, &daemon->proposer.sk);
        if (sign_status != AL_OK) {
            free(decoded);
            return sign_status;
        }
        al_u8 tx_encoded[2048];
        al_size tx_encoded_size = 0u;
        estatus = al_tx_encode(&tx,
                               (al_bytes_mut){tx_encoded, sizeof(tx_encoded)},
                               &tx_encoded_size);
        if (estatus != AL_OK) {
            free(decoded);
            return estatus;
        }
        al_hash256 tx_hash;
        estatus = al_node_submit_transaction(
            &daemon->node, al_bytes_make(tx_encoded, tx_encoded_size),
            &tx_hash);
        free(decoded);
        if (estatus != AL_OK) {
            return al_rpc_respond_error(body, -32050,
                                        al_status_str(estatus));
        }
        al_json_writer_raw(body, "{\"hash\":");
        al_json_writer_hex(body, al_bytes_make(tx_hash.bytes, AL_HASH_SIZE));
        al_json_writer_raw(body, "}");
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

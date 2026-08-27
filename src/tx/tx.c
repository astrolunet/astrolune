#include "astrolune/tx.h"
#include "internal/common.h"

#include <string.h>

#define TX_FIXED_ENVELOPE_SIZE 191u

typedef struct tx_host_context {
    al_state_txn *state;
    al_receipt   *receipt;
    al_vm_config  vm;
} tx_host_context;

static al_bool tx_type_valid(al_tx_type type) {
    return (type >= AL_TX_TRANSFER && type <= AL_TX_POTB) ? AL_TRUE : AL_FALSE;
}

static al_bool potb_operation_valid(al_potb_operation operation) {
    return (operation >= AL_POTB_REGISTER &&
            operation <= AL_POTB_COMMITTEE_VOTE) ? AL_TRUE : AL_FALSE;
}

static const char *vm_hash_domain_tag(al_u64 domain) {
    if (domain > AL_VM_HASH_BLOCK) return NULL;
    switch ((al_vm_hash_domain)domain) {
    case AL_VM_HASH_CONTRACT_DATA: return AL_TAG_CONTRACT_DATA;
    case AL_VM_HASH_ADDRESS: return AL_TAG_ADDRESS;
    case AL_VM_HASH_STORAGE_KEY: return AL_TAG_STORAGE_KEY;
    case AL_VM_HASH_STORAGE_VALUE: return AL_TAG_STORAGE_VALUE;
    case AL_VM_HASH_EVENT: return AL_TAG_EVENT;
    case AL_VM_HASH_POTB_RECORD: return AL_TAG_POTB_RECORD;
    case AL_VM_HASH_TRANSACTION: return AL_TAG_TX;
    case AL_VM_HASH_BLOCK: return AL_TAG_BLOCK;
    case AL_VM_HASH_DOMAIN_SENTINEL: break;
    }
    return NULL;
}

static al_bytes tx_payload(const al_transaction *tx) {
    if (tx->type == AL_TX_DEPLOY) return tx->body.deploy.container;
    if (tx->type == AL_TX_CALL) return tx->body.call.calldata;
    if (tx->type == AL_TX_POTB) return tx->body.potb.data;
    return al_bytes_empty();
}

static al_amount tx_value(const al_transaction *tx) {
    if (tx->type == AL_TX_TRANSFER) return tx->body.transfer.amount;
    if (tx->type == AL_TX_DEPLOY) return tx->body.deploy.value;
    if (tx->type == AL_TX_CALL) return tx->body.call.value;
    return 0u;
}

al_size al_tx_encoded_size(const al_transaction *tx) {
    if (tx == NULL || !tx_type_valid(tx->type)) return 0u;
    al_size body = 0u;
    al_bytes payload = tx_payload(tx);
    switch (tx->type) {
    case AL_TX_TRANSFER: body = 40u; break;
    case AL_TX_DEPLOY: body = 8u + al_varint_size(payload.len) + payload.len; break;
    case AL_TX_CALL: body = 44u + al_varint_size(payload.len) + payload.len; break;
    case AL_TX_POTB: body = 41u + al_varint_size(payload.len) + payload.len; break;
    case AL_TX_TYPE_SENTINEL: return 0u;
    }
    return TX_FIXED_ENVELOPE_SIZE + body;
}

al_status al_tx_validate_shape(const al_transaction *tx) {
    if (tx == NULL || tx->version != AL_TX_VERSION ||
        !tx_type_valid(tx->type)) {
        return AL_ERR_INVALID_ARG;
    }
    al_bytes payload = tx_payload(tx);
    if (payload.len > AL_TX_MAX_PAYLOAD ||
        (payload.data == NULL && payload.len != 0u) ||
        al_tx_encoded_size(tx) > AL_TX_MAX_SIZE) {
        return AL_ERR_OUT_OF_RANGE;
    }
    switch (tx->type) {
    case AL_TX_TRANSFER:
        if (al_address_is_zero(&tx->body.transfer.recipient) ||
            tx->body.transfer.amount == 0u) return AL_ERR_INVALID_ARG;
        break;
    case AL_TX_DEPLOY:
        if (payload.len == 0u) return AL_ERR_INVALID_ARG;
        break;
    case AL_TX_CALL:
        if (al_address_is_zero(&tx->body.call.contract))
            return AL_ERR_INVALID_ARG;
        break;
    case AL_TX_POTB:
        if (!potb_operation_valid(tx->body.potb.operation))
            return AL_ERR_INVALID_ARG;
        break;
    case AL_TX_TYPE_SENTINEL:
        return AL_ERR_INVALID_ARG;
    }
    return AL_OK;
}

static void tx_write_resources(al_writer *writer, al_resources value) {
    al_writer_u64(writer, value.compute);
    al_writer_u64(writer, value.memory);
    al_writer_u64(writer, value.storage);
    al_writer_u64(writer, value.bandwidth);
}

static al_resources tx_read_resources(al_reader *reader) {
    al_resources value;
    value.compute = al_reader_u64(reader);
    value.memory = al_reader_u64(reader);
    value.storage = al_reader_u64(reader);
    value.bandwidth = al_reader_u64(reader);
    return value;
}

static void tx_write(const al_transaction *tx, al_writer *writer,
                     al_bool include_signature) {
    al_writer_u16(writer, tx->version);
    al_writer_u32(writer, tx->chain_id);
    al_writer_u64(writer, tx->expiry_height);
    al_writer_raw(writer, tx->sender.bytes, AL_PUBKEY_SIZE);
    al_writer_u64(writer, tx->nonce);
    tx_write_resources(writer, tx->resource_limit);
    tx_write_resources(writer, tx->max_base_price);
    al_writer_u64(writer, tx->tip);
    al_writer_u8(writer, (al_u8)tx->type);
    switch (tx->type) {
    case AL_TX_TRANSFER:
        al_writer_address(writer, &tx->body.transfer.recipient);
        al_writer_u64(writer, tx->body.transfer.amount);
        break;
    case AL_TX_DEPLOY:
        al_writer_u64(writer, tx->body.deploy.value);
        al_writer_varint(writer, tx->body.deploy.container.len);
        al_writer_raw(writer, tx->body.deploy.container.data,
                      tx->body.deploy.container.len);
        break;
    case AL_TX_CALL:
        al_writer_address(writer, &tx->body.call.contract);
        al_writer_u64(writer, tx->body.call.value);
        al_writer_u32(writer, tx->body.call.entrypoint);
        al_writer_varint(writer, tx->body.call.calldata.len);
        al_writer_raw(writer, tx->body.call.calldata.data,
                      tx->body.call.calldata.len);
        break;
    case AL_TX_POTB:
        al_writer_u8(writer, (al_u8)tx->body.potb.operation);
        al_writer_raw(writer, tx->body.potb.target.bytes, AL_PUBKEY_SIZE);
        al_writer_u64(writer, tx->body.potb.amount);
        al_writer_varint(writer, tx->body.potb.data.len);
        al_writer_raw(writer, tx->body.potb.data.data, tx->body.potb.data.len);
        break;
    case AL_TX_TYPE_SENTINEL:
        break;
    }
    if (include_signature)
        al_writer_raw(writer, tx->signature.bytes, AL_SIGNATURE_SIZE);
}

al_status al_tx_encode(const al_transaction *tx, al_bytes_mut out,
                       al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    AL_TRY(al_tx_validate_shape(tx));
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    tx_write(tx, &writer, AL_TRUE);
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

static al_bytes tx_read_payload(al_reader *reader) {
    al_u64 length = al_reader_varint(reader);
    if (length > AL_TX_MAX_PAYLOAD || length > (al_u64)SIZE_MAX) {
        al_reader_fail(reader, AL_ERR_OUT_OF_RANGE);
        return al_bytes_empty();
    }
    return al_reader_take(reader, (al_size)length);
}

al_status al_tx_decode(al_bytes encoded, al_transaction *out) {
    if (out == NULL || encoded.len > AL_TX_MAX_SIZE) return AL_ERR_INVALID_ARG;
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_memzero(out, sizeof(*out));
    out->version = al_reader_u16(&reader);
    out->chain_id = al_reader_u32(&reader);
    out->expiry_height = al_reader_u64(&reader);
    al_reader_bytes(&reader, out->sender.bytes, AL_PUBKEY_SIZE);
    out->nonce = al_reader_u64(&reader);
    out->resource_limit = tx_read_resources(&reader);
    out->max_base_price = tx_read_resources(&reader);
    out->tip = al_reader_u64(&reader);
    al_u8 type = al_reader_u8(&reader);
    out->type = (al_tx_type)type;
    switch (out->type) {
    case AL_TX_TRANSFER:
        al_reader_address(&reader, &out->body.transfer.recipient);
        out->body.transfer.amount = al_reader_u64(&reader);
        break;
    case AL_TX_DEPLOY:
        out->body.deploy.value = al_reader_u64(&reader);
        out->body.deploy.container = tx_read_payload(&reader);
        break;
    case AL_TX_CALL:
        al_reader_address(&reader, &out->body.call.contract);
        out->body.call.value = al_reader_u64(&reader);
        out->body.call.entrypoint = al_reader_u32(&reader);
        out->body.call.calldata = tx_read_payload(&reader);
        break;
    case AL_TX_POTB: {
        al_u8 operation = al_reader_u8(&reader);
        out->body.potb.operation = (al_potb_operation)operation;
        al_reader_bytes(&reader, out->body.potb.target.bytes, AL_PUBKEY_SIZE);
        out->body.potb.amount = al_reader_u64(&reader);
        out->body.potb.data = tx_read_payload(&reader);
        break;
    }
    case AL_TX_TYPE_SENTINEL:
    default:
        al_reader_fail(&reader, AL_ERR_MALFORMED);
        break;
    }
    al_reader_bytes(&reader, out->signature.bytes, AL_SIGNATURE_SIZE);
    AL_TRY(al_reader_finish(&reader));
    return al_tx_validate_shape(out);
}

static void hash_u8(al_sha256_ctx *ctx, al_u8 value) {
    al_sha256_update(ctx, &value, 1u);
}

static void hash_u16(al_sha256_ctx *ctx, al_u16 value) {
    al_u8 bytes[2]; al_store_le16(bytes, value);
    al_sha256_update(ctx, bytes, sizeof(bytes));
}

static void hash_u32(al_sha256_ctx *ctx, al_u32 value) {
    al_u8 bytes[4]; al_store_le32(bytes, value);
    al_sha256_update(ctx, bytes, sizeof(bytes));
}

static void hash_u64(al_sha256_ctx *ctx, al_u64 value) {
    al_u8 bytes[8]; al_store_le64(bytes, value);
    al_sha256_update(ctx, bytes, sizeof(bytes));
}

static void hash_varint(al_sha256_ctx *ctx, al_u64 value) {
    do {
        al_u8 byte = (al_u8)(value & 0x7fu);
        value >>= 7u;
        if (value != 0u) byte |= 0x80u;
        hash_u8(ctx, byte);
    } while (value != 0u);
}

static void hash_resources(al_sha256_ctx *ctx, al_resources value) {
    hash_u64(ctx, value.compute); hash_u64(ctx, value.memory);
    hash_u64(ctx, value.storage); hash_u64(ctx, value.bandwidth);
}

static void tx_hash_for(const al_transaction *tx, const char *tag,
                        al_bool include_signature, al_hash256 *out) {
    if (out == NULL) return;
    if (al_tx_validate_shape(tx) != AL_OK) {
        *out = al_hash_zero();
        return;
    }
    al_hash256 tag_hash;
    al_sha256(tag, strlen(tag), &tag_hash);
    al_sha256_ctx ctx;
    al_sha256_init(&ctx);
    al_sha256_update(&ctx, tag_hash.bytes, AL_HASH_SIZE);
    hash_u16(&ctx, tx->version); hash_u32(&ctx, tx->chain_id);
    hash_u64(&ctx, tx->expiry_height);
    al_sha256_update(&ctx, tx->sender.bytes, AL_PUBKEY_SIZE);
    hash_u64(&ctx, tx->nonce);
    hash_resources(&ctx, tx->resource_limit);
    hash_resources(&ctx, tx->max_base_price);
    hash_u64(&ctx, tx->tip); hash_u8(&ctx, (al_u8)tx->type);
    switch (tx->type) {
    case AL_TX_TRANSFER:
        al_sha256_update(&ctx, tx->body.transfer.recipient.bytes, AL_ADDRESS_SIZE);
        hash_u64(&ctx, tx->body.transfer.amount); break;
    case AL_TX_DEPLOY:
        hash_u64(&ctx, tx->body.deploy.value);
        hash_varint(&ctx, tx->body.deploy.container.len);
        al_sha256_update(&ctx, tx->body.deploy.container.data,
                         tx->body.deploy.container.len); break;
    case AL_TX_CALL:
        al_sha256_update(&ctx, tx->body.call.contract.bytes, AL_ADDRESS_SIZE);
        hash_u64(&ctx, tx->body.call.value);
        hash_u32(&ctx, tx->body.call.entrypoint);
        hash_varint(&ctx, tx->body.call.calldata.len);
        al_sha256_update(&ctx, tx->body.call.calldata.data,
                         tx->body.call.calldata.len); break;
    case AL_TX_POTB:
        hash_u8(&ctx, (al_u8)tx->body.potb.operation);
        al_sha256_update(&ctx, tx->body.potb.target.bytes, AL_PUBKEY_SIZE);
        hash_u64(&ctx, tx->body.potb.amount);
        hash_varint(&ctx, tx->body.potb.data.len);
        al_sha256_update(&ctx, tx->body.potb.data.data,
                         tx->body.potb.data.len); break;
    case AL_TX_TYPE_SENTINEL: break;
    }
    if (include_signature)
        al_sha256_update(&ctx, tx->signature.bytes, AL_SIGNATURE_SIZE);
    al_sha256_final(&ctx, out);
}

void al_tx_hash(const al_transaction *tx, al_hash256 *out) {
    tx_hash_for(tx, AL_TAG_TX, AL_TRUE, out);
}

void al_tx_signing_hash(const al_transaction *tx, al_hash256 *out) {
    tx_hash_for(tx, AL_TAG_TX_SIGNING, AL_FALSE, out);
}

al_status al_tx_sign(al_transaction *tx, const al_seckey *secret_key) {
    if (tx == NULL || secret_key == NULL) return AL_ERR_INVALID_ARG;
    AL_TRY(al_tx_validate_shape(tx));
    al_hash256 hash;
    al_tx_signing_hash(tx, &hash);
    return al_sign_hash(secret_key, &hash, &tx->signature);
}

al_status al_tx_verify(const al_transaction *tx) {
    if (tx == NULL) return AL_ERR_INVALID_ARG;
    AL_TRY(al_tx_validate_shape(tx));
    al_hash256 hash;
    al_tx_signing_hash(tx, &hash);
    return al_verify_hash(&tx->sender, &hash, &tx->signature);
}

static al_bool event_valid(const al_event *event) {
    return (event != NULL && event->data.len <= AL_TX_MAX_PAYLOAD &&
            (event->data.data != NULL || event->data.len == 0u))
               ? AL_TRUE : AL_FALSE;
}

static void event_write(const al_event *event, al_writer *writer) {
    al_writer_address(writer, &event->contract);
    al_writer_hash(writer, &event->topic);
    al_writer_varint(writer, event->data.len);
    al_writer_raw(writer, event->data.data, event->data.len);
}

al_status al_event_encode(const al_event *event, al_bytes_mut out,
                          al_size *written) {
    if (written == NULL || !event_valid(event))
        return AL_ERR_INVALID_ARG;
    *written = 0u;
    al_writer writer; al_writer_init(&writer, out.data, out.len);
    event_write(event, &writer);
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

static void event_read(al_reader *reader, al_event *out) {
    al_reader_address(reader, &out->contract);
    al_reader_hash(reader, &out->topic);
    al_u64 data_len = al_reader_varint(reader);
    if (data_len > AL_TX_MAX_PAYLOAD || data_len > (al_u64)SIZE_MAX) {
        al_reader_fail(reader, AL_ERR_OUT_OF_RANGE);
        data_len = 0u;
    }
    out->data = al_reader_take(reader, (al_size)data_len);
}

al_status al_event_decode(al_bytes encoded, al_event *out) {
    if (out == NULL || encoded.data == NULL || encoded.len > AL_TX_MAX_SIZE)
        return AL_ERR_INVALID_ARG;
    al_memzero(out, sizeof(*out));
    al_reader reader;
    al_reader_init(&reader, encoded);
    event_read(&reader, out);
    al_status status = al_reader_finish(&reader);
    if (status != AL_OK) al_memzero(out, sizeof(*out));
    return status;
}

void al_event_hash(const al_event *event, al_hash256 *out) {
    if (out == NULL) return;
    if (!event_valid(event)) {
        *out = al_hash_zero(); return;
    }
    al_hash256 tag; al_sha256(AL_TAG_EVENT, strlen(AL_TAG_EVENT), &tag);
    al_sha256_ctx ctx; al_sha256_init(&ctx);
    al_sha256_update(&ctx, tag.bytes, AL_HASH_SIZE);
    al_sha256_update(&ctx, event->contract.bytes, AL_ADDRESS_SIZE);
    al_sha256_update(&ctx, event->topic.bytes, AL_HASH_SIZE);
    hash_varint(&ctx, event->data.len);
    al_sha256_update(&ctx, event->data.data, event->data.len);
    al_sha256_final(&ctx, out);
}

static void receipt_write(const al_receipt *receipt, al_writer *writer) {
    al_writer_hash(writer, &receipt->transaction_hash);
    al_writer_u32(writer, (al_u32)receipt->status);
    tx_write_resources(writer, receipt->resources);
    al_writer_u64(writer, receipt->base_fee_burned);
    al_writer_u64(writer, receipt->tip_paid);
    al_writer_address(writer, &receipt->contract_address);
    al_writer_varint(writer, receipt->return_data.len);
    al_writer_raw(writer, receipt->return_data.data, receipt->return_data.len);
    al_writer_varint(writer, receipt->event_count);
    for (al_size i = 0u; i < receipt->event_count; ++i) {
        event_write(&receipt->events[i], writer);
    }
}

static al_bool receipt_valid(const al_receipt *receipt) {
    if (receipt == NULL || receipt->event_count > AL_TX_MAX_EVENTS ||
        (receipt->events == NULL && receipt->event_count != 0u) ||
        receipt->return_data.len > AL_TX_MAX_PAYLOAD ||
        (receipt->return_data.data == NULL && receipt->return_data.len != 0u))
        return AL_FALSE;
    for (al_size i = 0u; i < receipt->event_count; ++i)
        if (!event_valid(&receipt->events[i])) return AL_FALSE;
    return AL_TRUE;
}

al_status al_receipt_encode(const al_receipt *receipt, al_bytes_mut out,
                            al_size *written) {
    if (written == NULL || !receipt_valid(receipt)) return AL_ERR_INVALID_ARG;
    *written = 0u;
    al_writer writer; al_writer_init(&writer, out.data, out.len);
    receipt_write(receipt, &writer);
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

static al_bool receipt_status_valid(al_u32 status) {
    if (status > AL_ERR_EXPIRED) return AL_FALSE;
    switch ((al_status)status) {
    case AL_OK:
    case AL_ERR_INVALID_ARG: case AL_ERR_OUT_OF_RANGE:
    case AL_ERR_BUFFER_TOO_SMALL: case AL_ERR_UNSUPPORTED:
    case AL_ERR_NOT_FOUND: case AL_ERR_ALREADY_EXISTS:
    case AL_ERR_OUT_OF_MEMORY: case AL_ERR_IO:
    case AL_ERR_MALFORMED: case AL_ERR_NOT_CANONICAL:
    case AL_ERR_TRUNCATED: case AL_ERR_TRAILING_BYTES:
    case AL_ERR_BAD_SIGNATURE: case AL_ERR_BAD_PROOF:
    case AL_ERR_OUT_OF_GAS: case AL_ERR_VM_TRAP:
    case AL_ERR_STACK_OVERFLOW: case AL_ERR_INVALID_OPCODE:
    case AL_ERR_DIVIDE_BY_ZERO: case AL_ERR_ARITH_OVERFLOW:
    case AL_ERR_MEMORY_FAULT: case AL_ERR_CALL_DEPTH:
    case AL_ERR_REVERTED: case AL_ERR_RESOURCE_LIMIT:
    case AL_ERR_REENTRANCY: case AL_ERR_INSUFFICIENT_FUNDS:
    case AL_ERR_BAD_NONCE: case AL_ERR_STATE_CORRUPT:
    case AL_ERR_CONSENSUS_VIOLATION: case AL_ERR_EXPIRED:
        return AL_TRUE;
    case AL_STATUS_SENTINEL:
        break;
    }
    return AL_FALSE;
}

al_status al_receipt_decode(al_bytes encoded, al_arena *arena,
                            al_receipt *out) {
    if (out == NULL || arena == NULL || encoded.data == NULL ||
        encoded.len > AL_TX_MAX_SIZE)
        return AL_ERR_INVALID_ARG;
    al_arena_mark mark = al_arena_save(arena);
    al_memzero(out, sizeof(*out));
    al_reader reader;
    al_reader_init(&reader, encoded);
    al_reader_hash(&reader, &out->transaction_hash);
    al_u32 status = al_reader_u32(&reader);
    if (!receipt_status_valid(status)) al_reader_fail(&reader, AL_ERR_MALFORMED);
    out->status = (al_status)status;
    out->resources = tx_read_resources(&reader);
    out->base_fee_burned = al_reader_u64(&reader);
    out->tip_paid = al_reader_u64(&reader);
    al_reader_address(&reader, &out->contract_address);
    al_u64 return_len = al_reader_varint(&reader);
    if (return_len > AL_TX_MAX_PAYLOAD || return_len > (al_u64)SIZE_MAX) {
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
        return_len = 0u;
    }
    out->return_data = al_reader_take(&reader, (al_size)return_len);
    al_u64 event_count = al_reader_varint(&reader);
    if (event_count > AL_TX_MAX_EVENTS) {
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
        event_count = 0u;
    }
    out->events = AL_ARENA_NEW_ARRAY(arena, al_event, (al_size)event_count);
    if (out->events == NULL && event_count != 0u) {
        al_arena_restore(arena, mark);
        al_memzero(out, sizeof(*out));
        return AL_ERR_OUT_OF_MEMORY;
    }
    out->event_count = (al_size)event_count;
    for (al_size i = 0u; i < out->event_count; ++i)
        event_read(&reader, &out->events[i]);
    al_status decode_status = al_reader_finish(&reader);
    if (decode_status != AL_OK) {
        al_arena_restore(arena, mark);
        al_memzero(out, sizeof(*out));
    }
    return decode_status;
}

void al_receipt_hash(const al_receipt *receipt, al_hash256 *out) {
    if (out == NULL) return;
    if (!receipt_valid(receipt)) { *out = al_hash_zero(); return; }
    al_hash256 tag; al_sha256(AL_TAG_RECEIPT, strlen(AL_TAG_RECEIPT), &tag);
    al_sha256_ctx ctx; al_sha256_init(&ctx);
    al_sha256_update(&ctx, tag.bytes, AL_HASH_SIZE);
    al_sha256_update(&ctx, receipt->transaction_hash.bytes, AL_HASH_SIZE);
    hash_u32(&ctx, (al_u32)receipt->status);
    hash_resources(&ctx, receipt->resources);
    hash_u64(&ctx, receipt->base_fee_burned);
    hash_u64(&ctx, receipt->tip_paid);
    al_sha256_update(&ctx, receipt->contract_address.bytes, AL_ADDRESS_SIZE);
    hash_varint(&ctx, receipt->return_data.len);
    al_sha256_update(&ctx, receipt->return_data.data, receipt->return_data.len);
    hash_varint(&ctx, receipt->event_count);
    for (al_size i = 0u; i < receipt->event_count; ++i) {
        al_hash256 event_hash; al_event_hash(&receipt->events[i], &event_hash);
        al_sha256_update(&ctx, event_hash.bytes, AL_HASH_SIZE);
    }
    al_sha256_final(&ctx, out);
}

static al_bool memory_range(al_bytes_mut memory, al_u64 offset, al_u64 length) {
    return (offset <= memory.len && length <= memory.len - (al_size)offset)
               ? AL_TRUE : AL_FALSE;
}

static al_status host_memory(al_vm_host_io *io, al_u64 offset, al_u64 length) {
    if (!memory_range(io->memory, offset, length)) return AL_ERR_MEMORY_FAULT;
    if (length != 0u) {
        al_u64 pages = (offset + length + AL_VM_MEMORY_PAGE_SIZE - 1u) /
                       AL_VM_MEMORY_PAGE_SIZE;
        if (pages > io->resources->memory) io->resources->memory = pages;
    }
    return AL_OK;
}

static al_status memory_address(al_bytes_mut memory, al_u64 offset,
                                al_address *out) {
    if (!memory_range(memory, offset, AL_ADDRESS_SIZE))
        return AL_ERR_MEMORY_FAULT;
    al_memcpy(out->bytes, memory.data + (al_size)offset, AL_ADDRESS_SIZE);
    return AL_OK;
}

static al_status tx_host_invoke(void *opaque, al_vm_host_id id,
                                al_vm_host_io *io) {
    tx_host_context *host = (tx_host_context *)opaque;
    if (host == NULL || io == NULL || io->execution == NULL) return AL_ERR_INVALID_ARG;
    const al_u64 *a = io->arguments;
    switch (id) {
    case AL_VM_HOST_SENDER:
    case AL_VM_HOST_CURRENT_ADDRESS: {
        AL_TRY(host_memory(io, a[0], AL_ADDRESS_SIZE));
        const al_address *address = (id == AL_VM_HOST_SENDER)
            ? &io->execution->sender : &io->execution->current_contract;
        al_memcpy(io->memory.data + (al_size)a[0], address->bytes, AL_ADDRESS_SIZE);
        return AL_OK;
    }
    case AL_VM_HOST_BLOCK_HEIGHT:
        io->results[0] = io->execution->block_height; io->result_count = 1u; return AL_OK;
    case AL_VM_HOST_PROTOCOL_DAY:
        io->results[0] = io->execution->protocol_day; io->result_count = 1u; return AL_OK;
    case AL_VM_HOST_BALANCE: {
        AL_TRY(host_memory(io, a[0], AL_ADDRESS_SIZE));
        al_address address; AL_TRY(memory_address(io->memory, a[0], &address));
        al_account account; al_status status = al_state_txn_get(host->state, &address, &account);
        if (status == AL_ERR_NOT_FOUND) account.balance = 0u;
        else if (status != AL_OK) return status;
        io->results[0] = account.balance; io->result_count = 1u; return AL_OK;
    }
    case AL_VM_HOST_TRANSFER: {
        AL_TRY(host_memory(io, a[0], AL_ADDRESS_SIZE));
        al_address recipient; AL_TRY(memory_address(io->memory, a[0], &recipient));
        return al_state_txn_transfer(host->state, &io->execution->current_contract,
                                     &recipient, a[1]);
    }
    case AL_VM_HOST_STORAGE_GET: {
        AL_TRY(host_memory(io, a[0], a[1]));
        AL_TRY(host_memory(io, a[2], a[3]));
        al_bytes value; al_status status = al_state_txn_storage_get(
            host->state, &io->execution->current_contract,
            al_bytes_make(io->memory.data + (al_size)a[0], (al_size)a[1]),
            io->arena, &value);
        if (status == AL_ERR_NOT_FOUND) {
            io->results[0] = UINT64_MAX; io->result_count = 1u; return AL_OK;
        }
        AL_TRY(status);
        if (value.len > a[3]) return AL_ERR_MEMORY_FAULT;
        if (value.len != 0u)
            al_memcpy(io->memory.data + (al_size)a[2], value.data, value.len);
        io->results[0] = value.len; io->result_count = 1u; return AL_OK;
    }
    case AL_VM_HOST_STORAGE_SET:
        AL_TRY(host_memory(io, a[0], a[1]));
        AL_TRY(host_memory(io, a[2], a[3]));
        return al_state_txn_storage_set(host->state,
            &io->execution->current_contract,
            al_bytes_make(io->memory.data + (al_size)a[0], (al_size)a[1]),
            al_bytes_make(io->memory.data + (al_size)a[2], (al_size)a[3]));
    case AL_VM_HOST_STORAGE_DELETE:
        AL_TRY(host_memory(io, a[0], a[1]));
        return al_state_txn_storage_delete(host->state,
            &io->execution->current_contract,
            al_bytes_make(io->memory.data + (al_size)a[0], (al_size)a[1]));
    case AL_VM_HOST_EMIT_EVENT: {
        AL_TRY(host_memory(io, a[0], a[1]));
        AL_TRY(host_memory(io, a[2], a[3]));
        if (host->receipt->event_count == AL_TX_MAX_EVENTS)
            return AL_ERR_RESOURCE_LIMIT;
        al_event *event = &host->receipt->events[host->receipt->event_count];
        event->contract = io->execution->current_contract;
        al_hash_tagged(AL_TAG_EVENT, io->memory.data + (al_size)a[0], (al_size)a[1],
                       &event->topic);
        al_u8 *copy = (al_u8 *)al_arena_dup(io->arena,
            io->memory.data + (al_size)a[2], (al_size)a[3]);
        if (copy == NULL && a[3] != 0u) return AL_ERR_OUT_OF_MEMORY;
        event->data = al_bytes_make(copy, (al_size)a[3]);
        ++host->receipt->event_count;
        return AL_OK;
    }
    case AL_VM_HOST_HASH_TAGGED: {
        AL_TRY(host_memory(io, a[0], a[1]));
        AL_TRY(host_memory(io, a[2], AL_HASH_SIZE));
        const char *tag = vm_hash_domain_tag(a[3]);
        if (tag == NULL) return AL_ERR_OUT_OF_RANGE;
        al_hash256 hash;
        al_hash_tagged(tag, io->memory.data + (al_size)a[0], (al_size)a[1],
                       &hash);
        al_memcpy(io->memory.data + (al_size)a[2], hash.bytes, AL_HASH_SIZE);
        return AL_OK;
    }
    case AL_VM_HOST_VERIFY_SIGNATURE: {
        AL_TRY(host_memory(io, a[0], AL_HASH_SIZE));
        AL_TRY(host_memory(io, a[1], AL_PUBKEY_SIZE));
        AL_TRY(host_memory(io, a[2], AL_SIGNATURE_SIZE));
        al_hash256 message;
        al_pubkey public_key;
        al_sig signature;
        al_memcpy(message.bytes, io->memory.data + (al_size)a[0], AL_HASH_SIZE);
        al_memcpy(public_key.bytes, io->memory.data + (al_size)a[1],
                  AL_PUBKEY_SIZE);
        al_memcpy(signature.bytes, io->memory.data + (al_size)a[2],
                  AL_SIGNATURE_SIZE);
        io->results[0] = (al_verify_hash(&public_key, &message, &signature) == AL_OK)
                             ? 1u : 0u;
        io->result_count = 1u;
        return AL_OK;
    }
    case AL_VM_HOST_CALL_CONTRACT: {
        AL_TRY(host_memory(io, a[0], AL_ADDRESS_SIZE));
        AL_TRY(host_memory(io, a[2], a[3]));
        AL_TRY(host_memory(io, a[4], a[5]));
        al_address target;
        AL_TRY(memory_address(io->memory, a[0], &target));
        for (al_size i = 0u; i < io->execution->active_contract_count; ++i) {
            if (al_address_eq(&target, &io->execution->active_contracts[i]))
                return AL_ERR_REENTRANCY;
        }
        al_bytes code;
        AL_TRY(al_state_txn_code_get(host->state, &target, &code));
        al_hash256 saved_root = host->state->root;
        al_size saved_events = host->receipt->event_count;
        if (a[1] != 0u) {
            al_status transfer = al_state_txn_transfer(
                host->state, &io->execution->current_contract, &target, a[1]);
            if (transfer != AL_OK) return transfer;
        }
        al_vm_execution_context child = *io->execution;
        child.current_contract = target;
        child.entrypoint = 0u;
        child.value = a[1];
        child.code = code;
        child.active_contracts = io->execution->active_contracts;
        child.active_contract_count = io->execution->active_contract_count;
        al_vm_result result;
        al_vm_host vm_host = { host, tx_host_invoke };
        al_status status = al_vm_execute(
            code, al_bytes_make(io->memory.data + (al_size)a[2], (al_size)a[3]),
            &host->vm, &child, &vm_host, io->arena, &result);
        al_resources combined;
        AL_TRY(al_resources_add(*io->resources, result.resources, &combined));
        *io->resources = combined;
        if (status != AL_OK) {
            host->state->root = saved_root;
            host->receipt->event_count = saved_events;
            if (status != AL_ERR_REVERTED) return status;
        }
        al_size copy_len = (result.return_data.len < (al_size)a[5])
                               ? result.return_data.len : (al_size)a[5];
        if (copy_len != 0u)
            al_memcpy(io->memory.data + (al_size)a[4], result.return_data.data,
                      copy_len);
        io->results[0] = (al_u64)status;
        io->results[1] = result.return_data.len;
        io->result_count = 2u;
        return AL_OK;
    }
    case AL_VM_HOST_ID_SENTINEL:
        return AL_ERR_UNSUPPORTED;
    }
    return AL_ERR_UNSUPPORTED;
}

static al_bool prices_cover(al_resources caps, al_resources prices) {
    return (caps.compute >= prices.compute && caps.memory >= prices.memory &&
            caps.storage >= prices.storage && caps.bandwidth >= prices.bandwidth)
               ? AL_TRUE : AL_FALSE;
}

static al_status tx_precheck(const al_transaction *tx, al_state *state,
                             const al_tx_context *context, al_address *sender,
                             al_amount *maximum_fee) {
    AL_TRY(al_tx_validate_shape(tx));
    if (state == NULL || context == NULL || context->arena == NULL)
        return AL_ERR_INVALID_ARG;
    if (tx->chain_id != context->chain_id) return AL_ERR_CONSENSUS_VIOLATION;
    if (context->block_height > tx->expiry_height) return AL_ERR_EXPIRED;
    al_size encoded_size = al_tx_encoded_size(tx);
    if (tx->resource_limit.bandwidth < encoded_size ||
        !prices_cover(tx->max_base_price, context->base_prices))
        return AL_ERR_RESOURCE_LIMIT;
    al_address_from_pubkey(&tx->sender, sender);
    al_account source; AL_TRY(al_state_get(state, sender, &source));
    if (source.nonce != tx->nonce) return AL_ERR_BAD_NONCE;
    if (source.nonce == UINT64_MAX) return AL_ERR_ARITH_OVERFLOW;
    AL_TRY(al_resources_fee(tx->resource_limit, tx->max_base_price, maximum_fee));
    al_u64 debit = 0u;
    if (al_add_overflow_u64(*maximum_fee, tx->tip, &debit) ||
        al_add_overflow_u64(debit, tx_value(tx), &debit)) return AL_ERR_ARITH_OVERFLOW;
    if (source.balance < debit) return AL_ERR_INSUFFICIENT_FUNDS;
    return al_tx_verify(tx);
}

static al_status tx_execute_body(const al_transaction *tx, al_state_txn *txn,
                                 const al_tx_context *context,
                                 const al_address *sender, al_receipt *receipt) {
    receipt->resources = al_resources_zero();
    receipt->resources.bandwidth = al_tx_encoded_size(tx);
    if (tx->type == AL_TX_TRANSFER) {
        receipt->resources.compute = 1u;
        return al_state_txn_transfer(txn, sender, &tx->body.transfer.recipient,
                                     tx->body.transfer.amount);
    }
    if (tx->type == AL_TX_DEPLOY) {
        al_vm_config vm = context->vm;
        vm.resource_limit = tx->resource_limit;
        AL_TRY(al_vm_validate(tx->body.deploy.container, &vm, context->arena));
        al_hash256 code_hash; al_sha256_bytes(tx->body.deploy.container, &code_hash);
        al_address_for_contract(sender, tx->nonce, &code_hash,
                                &receipt->contract_address);
        al_account existing;
        al_status existing_status = al_state_txn_get(
            txn, &receipt->contract_address, &existing);
        if (existing_status == AL_OK) return AL_ERR_ALREADY_EXISTS;
        if (existing_status != AL_ERR_NOT_FOUND) return existing_status;
        receipt->resources.compute = tx->body.deploy.container.len;
        receipt->resources.storage = tx->body.deploy.container.len;
        AL_TRY(al_state_txn_deploy(txn, &receipt->contract_address, 0u,
                                   tx->body.deploy.container));
        if (tx->body.deploy.value == 0u) return AL_OK;
        return al_state_txn_transfer(txn, sender, &receipt->contract_address,
                                     tx->body.deploy.value);
    }
    if (tx->type == AL_TX_POTB) {
        al_u8 key_bytes[41];
        key_bytes[0] = (al_u8)tx->body.potb.operation;
        al_memcpy(key_bytes + 1u, sender->bytes, AL_ADDRESS_SIZE);
        al_store_le64(key_bytes + 33u, tx->nonce);
        receipt->resources.compute = 10u;
        al_size record_len = 41u + al_varint_size(tx->body.potb.data.len) +
                             tx->body.potb.data.len;
        al_u8 *record = (al_u8 *)al_arena_alloc(context->arena, record_len);
        if (record == NULL) return AL_ERR_OUT_OF_MEMORY;
        al_writer writer;
        al_writer_init(&writer, record, record_len);
        al_writer_u8(&writer, (al_u8)tx->body.potb.operation);
        al_writer_raw(&writer, tx->body.potb.target.bytes, AL_PUBKEY_SIZE);
        al_writer_u64(&writer, tx->body.potb.amount);
        al_writer_varint(&writer, tx->body.potb.data.len);
        al_writer_raw(&writer, tx->body.potb.data.data,
                      tx->body.potb.data.len);
        AL_TRY(al_writer_finish(&writer));
        return al_state_txn_system_storage_set(
            txn, al_bytes_make(key_bytes, sizeof(key_bytes)),
            al_bytes_make(record, record_len));
    }

    AL_TRY(al_state_txn_transfer(txn, sender, &tx->body.call.contract,
                                 tx->body.call.value));
    al_bytes code; AL_TRY(al_state_txn_code_get(txn, &tx->body.call.contract, &code));
    al_vm_config vm = context->vm;
    vm.resource_limit = tx->resource_limit;
    tx_host_context host_context = { txn, receipt, vm };
    al_vm_host host = { &host_context, tx_host_invoke };
    al_vm_execution_context execution;
    al_memzero(&execution, sizeof(execution));
    execution.sender = *sender;
    execution.current_contract = tx->body.call.contract;
    execution.block_height = context->block_height;
    execution.protocol_day = context->protocol_day;
    execution.entrypoint = tx->body.call.entrypoint;
    execution.value = tx->body.call.value;
    execution.code = code;
    execution.state_txn = txn;
    al_vm_result result;
    al_status status = al_vm_execute(code, tx->body.call.calldata, &vm,
                                     &execution, &host, context->arena, &result);
    receipt->resources = result.resources;
    receipt->resources.bandwidth = al_tx_encoded_size(tx);
    receipt->return_data = result.return_data;
    return status;
}

static al_status credit_tip_part(al_state_txn *txn, const al_address *sender,
                                 const al_address *recipient,
                                 al_amount amount) {
    if (amount == 0u || al_address_eq(sender, recipient)) return AL_OK;
    return al_state_txn_transfer(txn, sender, recipient, amount);
}

static al_status credit_tip(al_state_txn *txn, const al_address *sender,
                            const al_tx_context *context, al_amount tip) {
    if (tip == 0u) return AL_OK;
    al_amount weighted = tip / 4u;
    al_amount bonded = (tip / 100u) * 15u + ((tip % 100u) * 15u) / 100u;
    al_amount flat = tip - weighted - bonded;
    AL_TRY(credit_tip_part(txn, sender, &context->tip_flat, flat));
    AL_TRY(credit_tip_part(txn, sender, &context->tip_weighted, weighted));
    AL_TRY(credit_tip_part(txn, sender, &context->tip_bonded, bonded));
    return AL_OK;
}

static al_status charge_included(al_state_txn *txn, const al_address *sender,
                                 const al_tx_context *context,
                                 al_receipt *receipt) {
    AL_TRY(al_resources_fee(receipt->resources, context->base_prices,
                            &receipt->base_fee_burned));
    al_account source; AL_TRY(al_state_txn_get(txn, sender, &source));
    if (source.balance < receipt->base_fee_burned)
        return AL_ERR_INSUFFICIENT_FUNDS;
    source.balance -= receipt->base_fee_burned;
    ++source.nonce;
    AL_TRY(al_state_txn_upsert(txn, &source));
    AL_TRY(credit_tip(txn, sender, context, receipt->tip_paid));
    return AL_OK;
}

al_status al_tx_apply(const al_transaction *tx, al_state *state,
                      const al_tx_context *context, al_receipt *receipt) {
    if (receipt == NULL) return AL_ERR_INVALID_ARG;
    al_memzero(receipt, sizeof(*receipt));
    al_address sender; al_amount maximum_fee = 0u;
    AL_TRY(tx_precheck(tx, state, context, &sender, &maximum_fee));
    AL_UNUSED(maximum_fee);
    receipt->events = AL_ARENA_NEW_ARRAY(context->arena, al_event, AL_TX_MAX_EVENTS);
    if (receipt->events == NULL) return AL_ERR_OUT_OF_MEMORY;
    receipt->tip_paid = tx->tip;
    al_tx_hash(tx, &receipt->transaction_hash);

    al_state_txn execution;
    AL_TRY(al_state_txn_begin(state, &execution));
    al_status execution_status = tx_execute_body(tx, &execution, context,
                                                 &sender, receipt);
    al_status resource_status = al_resources_add(receipt->resources,
                                                 execution.resources,
                                                 &receipt->resources);
    if (resource_status != AL_OK) execution_status = resource_status;
    if (execution_status == AL_OK &&
        !al_resources_within(receipt->resources, tx->resource_limit))
        execution_status = AL_ERR_RESOURCE_LIMIT;

    if (execution_status == AL_OK) {
        receipt->status = AL_OK;
        al_status charge = charge_included(&execution, &sender, context, receipt);
        if (charge != AL_OK) {
            al_state_txn_rollback(&execution);
            return charge;
        }
        return al_state_txn_commit(&execution);
    }

    al_state_txn_rollback(&execution);
    receipt->status = execution_status;
    receipt->event_count = 0u;
    receipt->return_data = al_bytes_empty();
    al_state_txn fees;
    AL_TRY(al_state_txn_begin(state, &fees));
    al_status charge = charge_included(&fees, &sender, context, receipt);
    if (charge == AL_OK) return al_state_txn_commit(&fees);
    al_state_txn_rollback(&fees);
    return charge;
}

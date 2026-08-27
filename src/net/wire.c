/* Codec for the framed P2P messages. See wire.h for the formats. */

#include "wire.h"
#include "internal/common.h"

al_status al_wire_header_decode(al_bytes data, al_wire_header *out) {
    if (data.len < AL_WIRE_HEADER_SIZE || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_reader reader;
    al_reader_init(&reader, al_bytes_slice(data, 0, AL_WIRE_HEADER_SIZE));

    if (al_reader_u8(&reader) != AL_WIRE_MAGIC_0 ||
        al_reader_u8(&reader) != AL_WIRE_MAGIC_1 ||
        al_reader_u8(&reader) != AL_WIRE_MAGIC_2 ||
        al_reader_u8(&reader) != AL_WIRE_MAGIC_3) {
        return AL_ERR_MALFORMED;
    }
    out->version = al_reader_u8(&reader);
    out->type = (al_wire_type)al_reader_u8(&reader);
    if (al_reader_u16(&reader) != 0u) return AL_ERR_NOT_CANONICAL;
    out->payload_len = al_reader_u32(&reader);

    if (out->version != AL_WIRE_PROTOCOL_VERSION ||
        out->payload_len > AL_WIRE_MAX_PAYLOAD) {
        return AL_ERR_OUT_OF_RANGE;
    }
    return al_reader_status(&reader);
}

void al_wire_header_encode(al_writer *writer, al_wire_type type,
                           al_u32 payload_len) {
    al_writer_u8(writer, AL_WIRE_MAGIC_0);
    al_writer_u8(writer, AL_WIRE_MAGIC_1);
    al_writer_u8(writer, AL_WIRE_MAGIC_2);
    al_writer_u8(writer, AL_WIRE_MAGIC_3);
    al_writer_u8(writer, AL_WIRE_PROTOCOL_VERSION);
    al_writer_u8(writer, (al_u8)type);
    al_writer_u16(writer, 0u); /* reserved */
    al_writer_u32(writer, payload_len);
}

/* --- HELLO ----------------------------------------------------------------- */

void al_wire_hello_encode(al_writer *writer, const al_wire_hello *hello) {
    al_writer_u32(writer, hello->protocol_version);
    al_writer_u16(writer, hello->listen_port);
    al_writer_hash(writer, &hello->genesis);
    al_writer_hash(writer, &hello->head);
    al_writer_u64(writer, hello->height);
}

al_status al_wire_hello_decode(al_bytes payload, al_wire_hello *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_reader reader;
    al_reader_init(&reader, payload);
    out->protocol_version = al_reader_u32(&reader);
    out->listen_port = al_reader_u16(&reader);
    al_reader_hash(&reader, &out->genesis);
    al_reader_hash(&reader, &out->head);
    out->height = al_reader_u64(&reader);
    AL_TRY(al_reader_finish(&reader));
    if (out->protocol_version != AL_WIRE_PROTOCOL_VERSION) {
        return AL_ERR_OUT_OF_RANGE;
    }
    return AL_OK;
}

/* --- PING / PONG ----------------------------------------------------------- */

void al_wire_ping_encode(al_writer *writer, const al_wire_ping *ping) {
    al_writer_u64(writer, ping->nonce);
}

al_status al_wire_ping_decode(al_bytes payload, al_wire_ping *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_reader reader;
    al_reader_init(&reader, payload);
    out->nonce = al_reader_u64(&reader);
    return al_reader_finish(&reader);
}

/* --- GET_BLOCKS ------------------------------------------------------------ */

void al_wire_get_blocks_encode(al_writer *writer,
                               const al_wire_get_blocks *request) {
    al_writer_u64(writer, request->start);
    al_writer_u32(writer, request->max_count);
}

al_status al_wire_get_blocks_decode(al_bytes payload,
                                    al_wire_get_blocks *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_reader reader;
    al_reader_init(&reader, payload);
    out->start = al_reader_u64(&reader);
    out->max_count = al_reader_u32(&reader);
    AL_TRY(al_reader_finish(&reader));
    /* An unbounded request would let one peer dictate unbounded work. */
    if (out->max_count == 0u || out->max_count > 256u) {
        return AL_ERR_OUT_OF_RANGE;
    }
    return AL_OK;
}

/* --- BLOCKS ---------------------------------------------------------------- */

al_status al_wire_blocks_begin(al_bytes payload,
                               al_wire_blocks_cursor *cursor) {
    if (cursor == NULL) return AL_ERR_INVALID_ARG;
    al_memzero(cursor, sizeof(*cursor));
    al_reader reader;
    al_reader_init(&reader, payload);
    al_u64 count = al_reader_varint(&reader);
    if (al_reader_status(&reader) != AL_OK) return AL_ERR_TRUNCATED;
    cursor->count = (al_size)count;
    cursor->remaining = al_bytes_slice(payload, reader.pos,
                                       payload.len - reader.pos);
    return AL_OK;
}

al_status al_wire_blocks_next(al_wire_blocks_cursor *cursor, al_bytes *entry) {
    if (cursor == NULL || entry == NULL) return AL_ERR_INVALID_ARG;
    if (cursor->index >= cursor->count) return AL_ERR_NOT_FOUND;

    al_reader reader;
    al_reader_init(&reader, cursor->remaining);
    al_u64 length = al_reader_varint(&reader);
    if (al_reader_status(&reader) != AL_OK ||
        length > (al_u64)al_reader_remaining(&reader)) {
        return AL_ERR_TRUNCATED;
    }
    *entry = al_bytes_slice(cursor->remaining, reader.pos, (al_size)length);
    cursor->remaining =
        al_bytes_slice(cursor->remaining, reader.pos + (al_size)length,
                       al_reader_remaining(&reader) - (al_size)length);
    cursor->index++;
    return AL_OK;
}

void al_wire_blocks_append(al_writer *writer, al_bytes encoded_block) {
    al_writer_varint(writer, (al_u64)encoded_block.len);
    al_writer_raw(writer, encoded_block.data, encoded_block.len);
}

al_status al_wire_finalized_block_encode(
    const al_wire_finalized_block *finalized, al_bytes_mut out,
    al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    if (finalized == NULL || finalized->certificate.data == NULL ||
        finalized->certificate.len == 0u || finalized->block.data == NULL ||
        finalized->block.len == 0u ||
        (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    if (finalized->certificate.len >
            AL_FINALITY_CERTIFICATE_MAX_ENCODED_SIZE ||
        finalized->block.len > AL_WIRE_MAX_PAYLOAD) {
        return AL_ERR_OUT_OF_RANGE;
    }
    al_size required = al_varint_size(finalized->certificate.len) +
                       finalized->certificate.len +
                       al_varint_size(finalized->block.len) +
                       finalized->block.len;
    if (required > AL_WIRE_MAX_PAYLOAD) return AL_ERR_OUT_OF_RANGE;
    *written = required;
    if (out.data == NULL || out.len < required) return AL_ERR_BUFFER_TOO_SMALL;
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    al_writer_varint(&writer, finalized->certificate.len);
    al_writer_raw(&writer, finalized->certificate.data,
                  finalized->certificate.len);
    al_writer_varint(&writer, finalized->block.len);
    al_writer_raw(&writer, finalized->block.data, finalized->block.len);
    AL_TRY(al_writer_finish(&writer));
    *written = al_writer_len(&writer);
    return AL_OK;
}

al_status al_wire_finalized_block_decode(al_bytes payload,
                                         al_wire_finalized_block *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_memzero(out, sizeof(*out));
    al_reader reader;
    al_reader_init(&reader, payload);
    al_u64 certificate_len = al_reader_varint(&reader);
    if (certificate_len == 0u ||
        certificate_len > AL_FINALITY_CERTIFICATE_MAX_ENCODED_SIZE ||
        certificate_len > al_reader_remaining(&reader)) {
        return AL_ERR_OUT_OF_RANGE;
    }
    out->certificate = al_reader_take(&reader, (al_size)certificate_len);
    al_u64 block_len = al_reader_varint(&reader);
    if (block_len == 0u || block_len > AL_WIRE_MAX_PAYLOAD ||
        block_len > al_reader_remaining(&reader)) {
        return AL_ERR_OUT_OF_RANGE;
    }
    out->block = al_reader_take(&reader, (al_size)block_len);
    return al_reader_finish(&reader);
}

al_status al_wire_proposal_encode(const al_wire_proposal *proposal,
                                  al_bytes_mut out, al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    if (proposal == NULL || proposal->block.data == NULL ||
        proposal->block.len == 0u ||
        (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_size required = AL_PROPOSAL_ENCODED_SIZE +
                       al_varint_size(proposal->block.len) +
                       proposal->block.len;
    *written = required;
    if (out.data == NULL || out.len < required) return AL_ERR_BUFFER_TOO_SMALL;
    al_size header_size = 0u;
    AL_TRY(al_consensus_proposal_encode(
        &proposal->consensus, out, &header_size));
    al_writer writer;
    al_writer_init(&writer, out.data + header_size, out.len - header_size);
    al_writer_varint(&writer, proposal->block.len);
    al_writer_raw(&writer, proposal->block.data, proposal->block.len);
    AL_TRY(al_writer_finish(&writer));
    *written = header_size + al_writer_len(&writer);
    return AL_OK;
}

al_status al_wire_proposal_decode(al_bytes payload, al_wire_proposal *out) {
    if (out == NULL) return AL_ERR_INVALID_ARG;
    al_memzero(out, sizeof(*out));
    if (payload.len < AL_PROPOSAL_ENCODED_SIZE + 1u) {
        return AL_ERR_TRUNCATED;
    }
    AL_TRY(al_consensus_proposal_decode(
        al_bytes_slice(payload, 0u, AL_PROPOSAL_ENCODED_SIZE),
        &out->consensus));
    al_reader reader;
    al_reader_init(
        &reader,
        al_bytes_slice(payload, AL_PROPOSAL_ENCODED_SIZE,
                       payload.len - AL_PROPOSAL_ENCODED_SIZE));
    al_u64 length = al_reader_varint(&reader);
    if (length == 0u || length > AL_WIRE_MAX_PAYLOAD ||
        length > al_reader_remaining(&reader)) {
        return AL_ERR_OUT_OF_RANGE;
    }
    out->block = al_reader_take(&reader, (al_size)length);
    return al_reader_finish(&reader);
}

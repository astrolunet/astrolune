/*
 * The P2P wire protocol.
 *
 * Every message is a frame: a fixed header followed by one payload. Frames are
 * the unit of scheduling for the whole transport, so the format is optimised
 * for cheap parsing and hard limits rather than extensibility - a peer that
 * cannot understand a frame has nothing useful to do with it anyway.
 *
 * Frame layout (little-endian throughout, matching the canonical encodings):
 *
 *   offset  size  field
 *        0     4  magic "ALNT"
 *        4     1  protocol version
 *        5     1  message type
 *        6     2  reserved (must be zero)
 *        8     4  payload length
 *
 * A frame larger than AL_WIRE_MAX_PAYLOAD is a protocol violation and drops
 * the connection: no legitimate message approaches the limit, so allowing one
 * would only be an invitation to exhaust node memory.
 */

#ifndef ASTROLUNE_NET_WIRE_H
#define ASTROLUNE_NET_WIRE_H

#include "astrolune/block.h"
#include "finality.h"

AL_EXTERN_C_BEGIN

#define AL_WIRE_MAGIC_0 ((al_u8)'A')
#define AL_WIRE_MAGIC_1 ((al_u8)'L')
#define AL_WIRE_MAGIC_2 ((al_u8)'N')
#define AL_WIRE_MAGIC_3 ((al_u8)'T')

#define AL_WIRE_PROTOCOL_VERSION 1u
#define AL_WIRE_HEADER_SIZE      12u
/* Blocks can carry tens of thousands of transactions; 16 MiB leaves generous
 * headroom above any legal block while still bounding per-peer memory. */
#define AL_WIRE_MAX_PAYLOAD      (16u * 1024u * 1024u)

typedef enum al_wire_type {
    AL_WIRE_HELLO     = 1,  /* handshake: identity, genesis, head          */
    AL_WIRE_PING      = 2,  /* keepalive probe                             */
    AL_WIRE_PONG      = 3,  /* keepalive reply                             */
    AL_WIRE_TX        = 4,  /* one canonical transaction                   */
    AL_WIRE_BLOCK     = 5,  /* one canonical block                         */
    AL_WIRE_GET_BLOCKS = 6, /* request a height range from a peer          */
    AL_WIRE_BLOCKS    = 7,  /* response: length-prefixed chain entries     */
    AL_WIRE_PROPOSAL  = 8,  /* signed consensus proposal plus block        */
    AL_WIRE_VOTE      = 9,  /* signed prevote or precommit                  */
    AL_WIRE_FINALITY  = 10, /* finalized block plus quorum certificate       */
    AL_WIRE_TYPE_SENTINEL = 0x7fffffff
} al_wire_type;

typedef struct al_wire_header {
    al_u32 version;
    al_wire_type type;
    al_u32 payload_len;
} al_wire_header;

/* Encode/decode the fixed frame header. Decode validates magic, version and
 * the payload bound; malformed frames never reach the dispatcher. */
void al_wire_header_encode(al_writer *writer, al_wire_type type,
                           al_u32 payload_len);
AL_NODISCARD al_status al_wire_header_decode(al_bytes data,
                                             al_wire_header *out);

/* --- HELLO -----------------------------------------------------------------
 * u32 protocol_version, u16 listen_port, hash256 genesis, hash256 head,
 * u64 height. The genesis hash is the chain binding: peers that disagree on it
 * are dropped before they can influence anything. */
typedef struct al_wire_hello {
    al_u32     protocol_version;
    al_u16     listen_port;
    al_hash256 genesis;
    al_hash256 head;
    al_height  height;
} al_wire_hello;

void al_wire_hello_encode(al_writer *writer, const al_wire_hello *hello);
AL_NODISCARD al_status al_wire_hello_decode(al_bytes payload,
                                            al_wire_hello *out);

/* --- PING / PONG ----------------------------------------------------------- */
typedef struct al_wire_ping { al_u64 nonce; } al_wire_ping;

void al_wire_ping_encode(al_writer *writer, const al_wire_ping *ping);
AL_NODISCARD al_status al_wire_ping_decode(al_bytes payload,
                                           al_wire_ping *out);

/* --- GET_BLOCKS ------------------------------------------------------------ */
typedef struct al_wire_get_blocks {
    al_height start;
    al_u32    max_count;
} al_wire_get_blocks;

void al_wire_get_blocks_encode(al_writer *writer,
                               const al_wire_get_blocks *request);
AL_NODISCARD al_status al_wire_get_blocks_decode(al_bytes payload,
                                                 al_wire_get_blocks *out);

/* --- BLOCKS ----------------------------------------------------------------
 * varint count, then count entries of varint length plus block bytes. Entries
 * are decoded one at a time by the caller through this cursor so that a single
 * multi-megabyte response never needs a second full-size buffer. */
typedef struct al_wire_blocks_cursor {
    al_bytes  remaining;
    al_size   index;
    al_size   count;
} al_wire_blocks_cursor;

AL_NODISCARD al_status al_wire_blocks_begin(al_bytes payload,
                                            al_wire_blocks_cursor *cursor);
/* Next entry; returns AL_OK with entry set, or AL_ERR_NOT_FOUND at the end. */
AL_NODISCARD al_status al_wire_blocks_next(al_wire_blocks_cursor *cursor,
                                           al_bytes *entry);

/* Append one entry to a BLOCKS payload being assembled into `writer`. */
void al_wire_blocks_append(al_writer *writer, al_bytes encoded_block);

/* A finalized chain entry is self-contained: a node can validate and execute
 * it even when it did not observe the original proposal round. */
typedef struct al_wire_finalized_block {
    al_bytes certificate;
    al_bytes block;
} al_wire_finalized_block;

AL_NODISCARD al_status al_wire_finalized_block_encode(
    const al_wire_finalized_block *finalized, al_bytes_mut out,
    al_size *written);
AL_NODISCARD al_status al_wire_finalized_block_decode(
    al_bytes payload, al_wire_finalized_block *out);

typedef struct al_wire_proposal {
    al_consensus_proposal consensus;
    al_bytes              block;
} al_wire_proposal;

AL_NODISCARD al_status al_wire_proposal_encode(
    const al_wire_proposal *proposal, al_bytes_mut out, al_size *written);
AL_NODISCARD al_status al_wire_proposal_decode(al_bytes payload,
                                               al_wire_proposal *out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_NET_WIRE_H */

/*
 * astrolune/hash.h - SHA-256, HMAC, HKDF and Merkle trees.
 *
 * Astrolune uses one hash function everywhere: SHA-256. A single primitive
 * keeps the consensus-critical surface small, is implementable in ~200 lines of
 * auditable C, is hardware-accelerated on every current CPU, and has decades of
 * analysis behind it. The cost is that it is slower than BLAKE3 on long inputs;
 * that trade is documented in docs/02-architecture/cryptography.md.
 *
 * Domain separation
 * ------------------------------------------------------------------------
 * Every structural hash in the protocol is tagged. Hashing a transaction and
 * hashing a block header must never be able to produce the same digest from the
 * same bytes, or an attacker could present one object where another is
 * expected. al_hash_tagged prefixes a domain string, and the AL_TAG_* constants
 * enumerate every domain the protocol defines.
 */

#ifndef ASTROLUNE_HASH_H
#define ASTROLUNE_HASH_H

#include "astrolune/base.h"
#include "astrolune/bytes.h"

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * SHA-256
 * -------------------------------------------------------------------------- */

#define AL_SHA256_BLOCK_SIZE  64
#define AL_SHA256_DIGEST_SIZE 32

/*
 * Streaming state. Named `al_sha256_ctx` rather than `al_sha256` because the
 * one-shot function below claims the bare name, and in C a typedef and a
 * function share one namespace - they cannot both be `al_sha256`.
 */
typedef struct al_sha256_ctx {
    al_u32  state[8];
    al_u64  bit_len;
    al_u8   buffer[AL_SHA256_BLOCK_SIZE];
    al_size buffer_len;
} al_sha256_ctx;

AL_PUBLIC void al_sha256_init(al_sha256_ctx *ctx);
AL_PUBLIC void al_sha256_update(al_sha256_ctx *ctx, const void *data, al_size len);
AL_PUBLIC void al_sha256_final(al_sha256_ctx *ctx, al_hash256 *out);

/* One-shot convenience form. */
AL_PUBLIC void al_sha256(const void *data, al_size len, al_hash256 *out);
AL_PUBLIC void al_sha256_bytes(al_bytes data, al_hash256 *out);

/* SHA-256 applied twice. Used where a length-extension property would be
 * exploitable and the input length is not itself authenticated. */
AL_PUBLIC void al_sha256d(const void *data, al_size len, al_hash256 *out);

/* --------------------------------------------------------------------------
 * Domain-separated hashing
 * -------------------------------------------------------------------------- */

/*
 * Every domain tag the protocol uses. Adding a hashed structure means adding a
 * tag here; reusing an existing tag for a new structure is a consensus bug.
 *
 * The tag is absorbed as SHA256(tag) || data rather than tag || data so that a
 * variable-length tag cannot shift the message boundary.
 */
#define AL_TAG_TX          "astrolune.tx.v1"
#define AL_TAG_TX_SIGNING  "astrolune.tx.signing.v1"
#define AL_TAG_BLOCK       "astrolune.block.v1"
#define AL_TAG_GENESIS     "astrolune.genesis.v1"
#define AL_TAG_HEADER      "astrolune.header.v1"
#define AL_TAG_ADDRESS     "astrolune.address.v1"
#define AL_TAG_CONTRACT    "astrolune.contract.v1"
#define AL_TAG_CONTRACT_DATA "astrolune.contract.data.v1"
#define AL_TAG_MERKLE_LEAF "astrolune.merkle.leaf.v1"
#define AL_TAG_MERKLE_NODE "astrolune.merkle.node.v1"
#define AL_TAG_SMT_LEAF    "astrolune.smt.leaf.v1"
#define AL_TAG_SMT_NODE    "astrolune.smt.node.v1"
#define AL_TAG_STORAGE_KEY "astrolune.storage.key.v1"
#define AL_TAG_ACCOUNT_KEY "astrolune.account.key.v1"
#define AL_TAG_ACCOUNT_VALUE "astrolune.account.value.v1"
#define AL_TAG_STORAGE_VALUE "astrolune.storage.value.v1"
#define AL_TAG_RECEIPT     "astrolune.receipt.v1"
#define AL_TAG_EVENT       "astrolune.event.v1"
#define AL_TAG_POTB_RECORD "astrolune.potb.record.v1"
#define AL_TAG_VOTE        "astrolune.vote.v1"
#define AL_TAG_PROPOSAL    "astrolune.proposal.v1"
#define AL_TAG_FINALITY    "astrolune.finality.v1"
#define AL_TAG_ATTESTATION "astrolune.attestation.v1"
#define AL_TAG_VRF         "astrolune.vrf.v1"
#define AL_TAG_COMMITTEE   "astrolune.committee.v1"
#define AL_TAG_EPOCH_SEED  "astrolune.epoch.seed.v1"
/* Distinct from AL_TAG_EPOCH_SEED on purpose: a commitment and the value it
 * commits to must not be derivable from one another, or the commit round would
 * leak the seed before anyone reveals. */
#define AL_TAG_EPOCH_COMMIT "astrolune.epoch.commit.v1"

AL_PUBLIC void al_hash_tagged(const char *tag, const void *data, al_size len,
                    al_hash256 *out);
AL_PUBLIC void al_hash_tagged_bytes(const char *tag, al_bytes data, al_hash256 *out);

/* Tagged hash of two digests, for tree interior nodes. */
AL_PUBLIC void al_hash_tagged_pair(const char *tag, const al_hash256 *left,
                         const al_hash256 *right, al_hash256 *out);

/* --------------------------------------------------------------------------
 * HMAC-SHA256 and HKDF
 * -------------------------------------------------------------------------- */

typedef struct al_hmac_ctx {
    al_sha256_ctx inner;
    al_sha256_ctx outer;
} al_hmac_ctx;

AL_PUBLIC void al_hmac_init(al_hmac_ctx *ctx, const void *key, al_size key_len);
AL_PUBLIC void al_hmac_update(al_hmac_ctx *ctx, const void *data, al_size len);
AL_PUBLIC void al_hmac_final(al_hmac_ctx *ctx, al_hash256 *out);

AL_PUBLIC void al_hmac_sha256(const void *key, al_size key_len,
                    const void *data, al_size len, al_hash256 *out);

/* HKDF (RFC 5869) over SHA-256. Deterministic key derivation for the VRF and
 * for the deterministic test keys. */
AL_PUBLIC void al_hkdf_extract(const void *salt, al_size salt_len,
                     const void *ikm, al_size ikm_len, al_hash256 *prk_out);

AL_PUBLIC AL_NODISCARD al_status al_hkdf_expand(const al_hash256 *prk,
                                      const void *info, al_size info_len,
                                      void *out, al_size out_len);

/* --------------------------------------------------------------------------
 * Hash utilities
 * -------------------------------------------------------------------------- */

AL_PUBLIC al_hash256 al_hash_zero(void);
AL_PUBLIC AL_NODISCARD al_bool al_hash_eq(const al_hash256 *a, const al_hash256 *b);
AL_PUBLIC AL_NODISCARD al_bool al_hash_is_zero(const al_hash256 *h);

/* Total order on digests. Used to canonicalise sets so that every node
 * serialises them in the same order. */
AL_PUBLIC int al_hash_cmp(const al_hash256 *a, const al_hash256 *b);

/* Bit `i` of a digest, counting from the most significant bit of byte 0.
 * This is the bit order the sparse Merkle tree descends in. */
AL_PUBLIC AL_NODISCARD al_bool al_hash_bit(const al_hash256 *h, al_size i);

/* --------------------------------------------------------------------------
 * Merkle tree (ordered, for transaction lists)
 *
 * Binary tree over an ordered sequence. Leaves and interior nodes use different
 * domain tags, which is what prevents the second-preimage attack where an
 * interior node is presented as a leaf. An odd node count promotes the last
 * node unchanged rather than duplicating it - duplication is the CVE-2012-2459
 * bug, where two distinct transaction lists hash to one root.
 * -------------------------------------------------------------------------- */

/* Root of `count` leaves. Empty input yields the all-zero digest. */
AL_PUBLIC void al_merkle_root(const al_hash256 *leaves, al_size count, al_hash256 *out);

/* Hash a leaf's contents into the form al_merkle_root expects. */
AL_PUBLIC void al_merkle_leaf(al_bytes data, al_hash256 *out);

/* Maximum proof length for a tree of `count` leaves. */
AL_PUBLIC al_size al_merkle_proof_max_len(al_size count);

/*
 * Inclusion proof for `index`. `proof_out` must hold at least
 * al_merkle_proof_max_len(count) digests; the length actually written is
 * returned through `proof_len_out`.
 */
AL_PUBLIC AL_NODISCARD al_status al_merkle_prove(const al_hash256 *leaves, al_size count,
                                       al_size index, al_hash256 *proof_out,
                                       al_size *proof_len_out);

/* Recompute the root from a leaf and its proof and compare against `root`. */
AL_PUBLIC AL_NODISCARD al_bool al_merkle_verify(const al_hash256 *leaf, al_size index,
                                      al_size count,
                                      const al_hash256 *proof, al_size proof_len,
                                      const al_hash256 *root);

AL_EXTERN_C_END

#endif /* ASTROLUNE_HASH_H */

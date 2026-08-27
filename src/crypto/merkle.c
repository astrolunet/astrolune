/*
 * Merkle tree over an ordered leaf sequence.
 *
 * Shape
 * ------------------------------------------------------------------------
 * The tree is defined recursively: split the leaf range at the largest power of
 * two strictly below the count, and hash the two subtree roots together.
 *
 *   root([x])      = x
 *   root(xs)       = H_node(root(xs[0:k]), root(xs[k:n])),  k = 2^floor(log2(n-1))
 *
 * This is the "promote the odd node" variant of level-by-level construction,
 * expressed as a recursion so that the root, the proof and the verifier all
 * derive from one definition rather than three implementations that have to
 * agree. Divergence between them is a consensus bug, and the recursion makes
 * divergence structurally impossible.
 *
 * Two properties matter and both are deliberate:
 *
 *   - Leaves and interior nodes use different domain tags. Without that, an
 *     interior node's digest can be presented as a leaf, which is the classic
 *     second-preimage attack on Merkle trees.
 *
 *   - An odd node is promoted unchanged, never duplicated. Duplicating it is
 *     CVE-2012-2459: two distinct transaction lists produce the same root, so a
 *     block can be mutated without changing its header.
 */

#include "astrolune/hash.h"

#include "internal/common.h"

/* Maximum tree depth. A tree deeper than this would need more than 2^64 leaves,
 * so this bound also caps every proof and scratch array below. */
#define AL_MERKLE_MAX_DEPTH 64

/* Largest power of two strictly less than `count`. Requires count >= 2. */
static al_size al_merkle_split(al_size count) {
    AL_ASSERT(count >= 2u);
    unsigned w = al_bit_width64((al_u64)(count - 1u));
    return (al_size)1u << (w - 1u);
}

void al_merkle_leaf(al_bytes data, al_hash256 *out) {
    al_hash_tagged_bytes(AL_TAG_MERKLE_LEAF, data, out);
}

/* Root of leaves[0, count). count >= 1. Recursion depth is log2(count) <= 64. */
static void al_merkle_range(const al_hash256 *leaves, al_size count,
                            al_hash256 *out) {
    if (count == 1u) {
        *out = leaves[0];
        return;
    }
    al_size    k = al_merkle_split(count);
    al_hash256 left, right;
    al_merkle_range(leaves, k, &left);
    al_merkle_range(leaves + k, count - k, &right);
    al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &left, &right, out);
}

void al_merkle_root(const al_hash256 *leaves, al_size count, al_hash256 *out) {
    if (count == 0u || leaves == NULL) {
        /* An empty list has a defined root: the zero digest. Callers compare
         * against it, so it must be a value and not an error. */
        *out = al_hash_zero();
        return;
    }
    al_merkle_range(leaves, count, out);
}

al_size al_merkle_proof_max_len(al_size count) {
    if (count <= 1u) {
        return 0u;
    }
    /* Depth of the tree: one sibling per level. */
    return (al_size)al_bit_width64((al_u64)(count - 1u));
}

al_status al_merkle_prove(const al_hash256 *leaves, al_size count,
                          al_size index, al_hash256 *proof_out,
                          al_size *proof_len_out) {
    if (leaves == NULL || proof_len_out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    if (count == 0u || index >= count) {
        return AL_ERR_OUT_OF_RANGE;
    }
    if (count > 1u && proof_out == NULL) {
        return AL_ERR_INVALID_ARG;
    }

    /* Descend from the root, recording the sibling subtree's root at each step.
     * That produces the path top-down; it is reversed at the end so that
     * proof[0] is the sibling adjacent to the leaf, which is the order
     * verifiers and every other Merkle implementation expect. */
    al_hash256 path[AL_MERKLE_MAX_DEPTH];
    al_size    depth = 0u;

    const al_hash256 *base = leaves;
    al_size           n    = count;
    al_size           i    = index;

    while (n > 1u) {
        AL_ASSERT(depth < AL_MERKLE_MAX_DEPTH);
        al_size k = al_merkle_split(n);
        if (i < k) {
            al_merkle_range(base + k, n - k, &path[depth]);
            n = k;
        } else {
            al_merkle_range(base, k, &path[depth]);
            base += k;
            i    -= k;
            n    -= k;
        }
        ++depth;
    }

    for (al_size j = 0u; j < depth; ++j) {
        proof_out[j] = path[depth - 1u - j];
    }
    *proof_len_out = depth;
    return AL_OK;
}

al_bool al_merkle_verify(const al_hash256 *leaf, al_size index, al_size count,
                         const al_hash256 *proof, al_size proof_len,
                         const al_hash256 *root) {
    if (leaf == NULL || root == NULL) {
        return AL_FALSE;
    }
    if (count == 0u || index >= count) {
        return AL_FALSE;
    }

    if (count == 1u) {
        /* Single leaf: the leaf *is* the root, and any proof material is a lie. */
        return (proof_len == 0u && al_hash_eq(leaf, root)) ? AL_TRUE : AL_FALSE;
    }
    if (proof == NULL) {
        return AL_FALSE;
    }

    /*
     * Reject an absurd length up front, before any hashing. This is only a bound:
     * because an odd node is promoted rather than duplicated, the tree is not
     * perfect and different leaves sit at different depths - leaf 2 of a 3-leaf
     * tree is one level from the root while leaves 0 and 1 are two. The *exact*
     * length is checked below against the descent this (index, count) implies,
     * which is what stops a short proof from presenting an interior node as the
     * root of a smaller tree.
     */
    if (proof_len > al_merkle_proof_max_len(count)) {
        return AL_FALSE;
    }

    /* Replay the same descent as al_merkle_prove to recover which side each
     * sibling was on. Only the path shape is needed, not the leaf data - which
     * is the whole point of an inclusion proof. */
    al_bool on_right[AL_MERKLE_MAX_DEPTH];
    al_size depth = 0u;
    al_size n     = count;
    al_size i     = index;

    while (n > 1u) {
        if (depth >= AL_MERKLE_MAX_DEPTH) {
            return AL_FALSE;
        }
        al_size k = al_merkle_split(n);
        if (i < k) {
            on_right[depth] = AL_FALSE;   /* our subtree is the left child */
            n = k;
        } else {
            on_right[depth] = AL_TRUE;
            i -= k;
            n -= k;
        }
        ++depth;
    }

    /* The exact check: the descent above determines the proof length completely,
     * so anything else is a forgery attempt or a corrupt proof. */
    if (depth != proof_len) {
        return AL_FALSE;
    }

    /* Fold upward. proof[j] pairs with the node at depth (depth-1-j). */
    al_hash256 acc = *leaf;
    for (al_size j = 0u; j < depth; ++j) {
        al_size level = depth - 1u - j;
        if (on_right[level]) {
            al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &proof[j], &acc, &acc);
        } else {
            al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &acc, &proof[j], &acc);
        }
    }
    return al_hash_eq(&acc, root);
}

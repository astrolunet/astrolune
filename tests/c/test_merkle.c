/*
 * Merkle tree.
 *
 * Three things are being tested here and only one of them is "does it compute a
 * hash":
 *
 *   - The shape is pinned by golden roots. The tree layout is consensus-visible,
 *     so a refactor that quietly changes how an odd leaf count is folded is a
 *     hard fork, and it has to fail here.
 *   - prove/verify agree with root for every leaf of every tree size in a range.
 *     They are three code paths over one recursive definition, and the only way
 *     to know they have not drifted apart is to check all three against each
 *     other exhaustively at small sizes.
 *   - The two classic attacks are covered: duplicating an odd node
 *     (CVE-2012-2459) is impossible by construction, and the leaf/node tag split
 *     that blocks the second-preimage substitution is checked directly.
 *
 * Golden values were computed independently in Python from the recursion in
 * core/crypto/merkle.c's header comment.
 */

#include "astrolune/hash.h"

#include "altest.h"

#define AL_TEST_SUITE_NAME "merkle"

#define AL_MAX_LEAVES 40

/* leaves[i] = al_merkle_leaf of the single letter 'a' + i. */
static void al_fill_leaves(al_hash256 *leaves, al_size count) {
    for (al_size i = 0u; i < count; ++i) {
        char c = (char)('a' + (int)(i % 26u));
        al_merkle_leaf(al_bytes_make(&c, 1u), &leaves[i]);
    }
}

AL_TEST(leaf_hashing) {
    al_hash256 leaf;
    al_merkle_leaf(al_bytes_from_cstr("abc"), &leaf);
    AL_CHECK_HASH_HEX(leaf,
        "1eb3ac2e2ab7f4eb3ceb43abbefcd64b76bdab8311575069ed9d62e7dabe5ba8");

    /* A leaf hash must not equal the interior-node hash of the same bytes, or an
     * interior node could be substituted for a leaf. */
    al_hash256 zero = al_hash_zero(), as_node;
    al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &zero, &zero, &as_node);

    al_u8      sixty_four[64];
    al_hash256 as_leaf;
    memset(sixty_four, 0, sizeof(sixty_four));
    al_merkle_leaf(al_bytes_make(sixty_four, sizeof(sixty_four)), &as_leaf);
    AL_CHECK(!al_hash_eq(&as_leaf, &as_node));
}

AL_TEST(root_golden_values) {
    al_hash256 leaves[8];
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    static const char *expected[8] = {
        "f4809c6f12fadcd46756eb8ff2b1685f293947a74045099c62afba213d49ce4a",
        "a801d35ead1e2de2a1f51cc530995570ea47944bab1f03163f9e3d75ffd4a320",
        "47e0289bf8159b10c3212520a52801099ae2c262e2bb665ab71cfa12b024d21b",
        "6af2c9458dc3b93882d8f36cd2da44b2da129d669a5465bf301a34104c654c83",
        "9b92fbd47a924bacf5073824e2fea26b8a896299c8564f48a09097f6b680044c",
        "e7861f7a40315ba5230919b7999c17a0ccdcc593efee3b29d18621eed00d3c5c",
        "2ac8ab0bc90155335145d4e18d8a01c1b4a50118c8437c7d9f06c4411d1a176d",
        "e74c9028a6dff35326bd21c84a32c39f211c2cfd02755c49ce0df30026b4c640",
    };

    for (al_size n = 1u; n <= AL_COUNTOF(leaves); ++n) {
        al_hash256 root;
        al_merkle_root(leaves, n, &root);
        al_test_check_hex("root", __FILE__, __LINE__, root.bytes, AL_HASH_SIZE,
                          expected[n - 1u]);
    }

    /* A single leaf is its own root - no wrapping node. That is what makes the
     * n=1 proof empty and it must stay true. */
    al_hash256 one;
    al_merkle_root(leaves, 1u, &one);
    AL_CHECK(al_hash_eq(&one, &leaves[0]));

    /* The empty tree has a defined root rather than an error. */
    al_hash256 empty;
    al_merkle_root(leaves, 0u, &empty);
    AL_CHECK(al_hash_is_zero(&empty));

    al_merkle_root(NULL, 5u, &empty);
    AL_CHECK(al_hash_is_zero(&empty));
}

AL_TEST(root_depends_on_order) {
    al_hash256 leaves[4], swapped[4], a, b;
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    memcpy(swapped, leaves, sizeof(leaves));
    swapped[0] = leaves[1];
    swapped[1] = leaves[0];

    al_merkle_root(leaves, 4u, &a);
    al_merkle_root(swapped, 4u, &b);
    AL_CHECK(!al_hash_eq(&a, &b));
}

AL_TEST(odd_node_is_promoted_not_duplicated) {
    /*
     * CVE-2012-2459. If an odd trailing node were duplicated to pad the level,
     * the 3-leaf list [a,b,c] and the 4-leaf list [a,b,c,c] would fold to the
     * same root - so a block's transaction list could be altered without
     * changing its header. Promotion makes the two roots differ.
     */
    al_hash256 leaves[4];
    al_fill_leaves(leaves, 3u);
    leaves[3] = leaves[2];

    al_hash256 three, four;
    al_merkle_root(leaves, 3u, &three);
    al_merkle_root(leaves, 4u, &four);
    AL_CHECK(!al_hash_eq(&three, &four));

    /* Same shape one level up: [a..e] vs [a..e,e]. */
    al_hash256 five[6];
    al_fill_leaves(five, 5u);
    five[5] = five[4];

    al_hash256 r5, r6;
    al_merkle_root(five, 5u, &r5);
    al_merkle_root(five, 6u, &r6);
    AL_CHECK(!al_hash_eq(&r5, &r6));
}

AL_TEST(proof_lengths) {
    /* al_merkle_proof_max_len is an upper bound, and it has to be a *tight* one
     * because callers size their proof buffers with it. */
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(0u), 0u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(1u), 0u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(2u), 1u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(3u), 2u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(4u), 2u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(5u), 3u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(8u), 3u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(9u), 4u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(1024u), 10u);
    AL_CHECK_EQ_U64(al_merkle_proof_max_len(1025u), 11u);

    al_hash256 leaves[AL_MAX_LEAVES];
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    /*
     * Because an odd node is promoted rather than duplicated, the tree is not
     * perfect and proof lengths are ragged: in a 3-leaf tree, leaf 2 sits one
     * level below the root while leaves 0 and 1 sit two. The bound must hold for
     * every leaf, and at least one leaf must actually reach it.
     */
    static const al_size expected_len_5[5] = {3u, 3u, 3u, 3u, 1u};
    for (al_size i = 0u; i < 5u; ++i) {
        al_hash256 proof[8];
        al_size    len = 0u;
        AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 5u, i, proof, &len), AL_OK);
        AL_CHECK_EQ_U64(len, expected_len_5[i]);
    }

    for (al_size n = 1u; n <= AL_COUNTOF(leaves); ++n) {
        al_size bound   = al_merkle_proof_max_len(n);
        al_size reached = 0u;
        for (al_size i = 0u; i < n; ++i) {
            al_hash256 proof[AL_MAX_LEAVES];
            al_size    len = 0u;
            AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, n, i, proof, &len), AL_OK);
            AL_CHECK(len <= bound);
            if (len == bound) {
                reached = 1u;
            }
        }
        AL_CHECK_MSG(reached != 0u, "bound is not tight");
    }
}

AL_TEST(prove_verify_roundtrip) {
    al_hash256 leaves[AL_MAX_LEAVES];
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    /* Exhaustive over every tree size and every leaf. root, prove and verify are
     * three readings of one recursion; this is what keeps them in step. */
    for (al_size n = 1u; n <= AL_COUNTOF(leaves); ++n) {
        al_hash256 root;
        al_merkle_root(leaves, n, &root);

        for (al_size i = 0u; i < n; ++i) {
            al_hash256 proof[AL_MAX_LEAVES];
            al_size    len = 0u;
            AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, n, i, proof, &len), AL_OK);
            AL_CHECK(al_merkle_verify(&leaves[i], i, n, proof, len, &root));
        }
    }
}

AL_TEST(verify_rejects_tampering) {
    al_hash256 leaves[7];
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    al_hash256 root;
    al_merkle_root(leaves, 7u, &root);

    al_hash256 proof[4];
    al_size    len = 0u;
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 7u, 3u, proof, &len), AL_OK);
    AL_CHECK(al_merkle_verify(&leaves[3], 3u, 7u, proof, len, &root));

    /* Wrong leaf. */
    AL_CHECK(!al_merkle_verify(&leaves[4], 3u, 7u, proof, len, &root));

    /* Right leaf, wrong claimed position. Without this check a valid proof could
     * be replayed to show the leaf sits somewhere it does not. */
    AL_CHECK(!al_merkle_verify(&leaves[3], 2u, 7u, proof, len, &root));

    /*
     * Wrong tree size, where the size actually changes the descent.
     *
     * Leaf 6 sits at depth 2 in a 7-leaf tree (it is the promoted odd node) but
     * at depth 3 in an 8-leaf tree, so the exact-length check rejects it.
     *
     * Note what this does *not* claim. An inclusion proof authenticates the leaf,
     * its index and the root - not the leaf count. Where two counts imply the
     * same descent shape the fold is bit-identical and both verify: index 3 is
     * LRR at depth 3 in a 7-leaf tree and in an 8-leaf tree alike, so passing
     * count=8 against a 7-leaf root succeeds. That is a property of Merkle proofs
     * generally, not a defect here, and it is safe because the root still binds
     * the contents. Anything that needs the count authenticated must commit to it
     * separately - which is why the block header carries an explicit
     * transaction count rather than inferring it from the proofs.
     */
    al_hash256 proof6[4];
    al_size    len6 = 0u;
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 7u, 6u, proof6, &len6), AL_OK);
    AL_CHECK_EQ_U64(len6, 2u);
    AL_CHECK(al_merkle_verify(&leaves[6], 6u, 7u, proof6, len6, &root));
    AL_CHECK(!al_merkle_verify(&leaves[6], 6u, 8u, proof6, len6, &root));

    /* Corrupted sibling. */
    al_hash256 bad[4];
    memcpy(bad, proof, sizeof(proof));
    bad[0].bytes[0] ^= 0x01u;
    AL_CHECK(!al_merkle_verify(&leaves[3], 3u, 7u, bad, len, &root));

    /* Truncated and over-long proofs. A short proof would otherwise let an
     * interior node be presented as the root of a smaller tree. */
    AL_CHECK(!al_merkle_verify(&leaves[3], 3u, 7u, proof, len - 1u, &root));
    AL_CHECK(!al_merkle_verify(&leaves[3], 3u, 7u, proof, len + 1u, &root));

    /* Wrong root. */
    al_hash256 other_root;
    al_merkle_root(leaves, 6u, &other_root);
    AL_CHECK(!al_merkle_verify(&leaves[3], 3u, 7u, proof, len, &other_root));

    /* Out-of-range index and empty tree are rejected, not undefined. */
    AL_CHECK(!al_merkle_verify(&leaves[3], 7u, 7u, proof, len, &root));
    AL_CHECK(!al_merkle_verify(&leaves[3], 0u, 0u, proof, len, &root));
    AL_CHECK(!al_merkle_verify(NULL, 3u, 7u, proof, len, &root));
    AL_CHECK(!al_merkle_verify(&leaves[3], 3u, 7u, NULL, len, &root));
}

AL_TEST(single_leaf_proof_is_empty) {
    al_hash256 leaves[1];
    al_fill_leaves(leaves, 1u);

    al_hash256 proof[1];
    al_size    len = 1u;
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 1u, 0u, proof, &len), AL_OK);
    AL_CHECK_EQ_U64(len, 0u);

    AL_CHECK(al_merkle_verify(&leaves[0], 0u, 1u, NULL, 0u, &leaves[0]));

    /* A one-leaf tree with proof material attached is a lie: the leaf is the
     * root, so there is nothing to combine it with. */
    al_hash256 junk = al_hash_zero();
    AL_CHECK(!al_merkle_verify(&leaves[0], 0u, 1u, &junk, 1u, &leaves[0]));
}

AL_TEST(prove_argument_validation) {
    al_hash256 leaves[4];
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    al_hash256 proof[2];
    al_size    len = 0u;

    AL_CHECK_EQ_STATUS(al_merkle_prove(NULL, 4u, 0u, proof, &len),
                       AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 4u, 0u, proof, NULL),
                       AL_ERR_INVALID_ARG);
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 0u, 0u, proof, &len),
                       AL_ERR_OUT_OF_RANGE);
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 4u, 4u, proof, &len),
                       AL_ERR_OUT_OF_RANGE);
    AL_CHECK_EQ_STATUS(al_merkle_prove(leaves, 4u, 0u, NULL, &len),
                       AL_ERR_INVALID_ARG);
}

AL_TEST(interior_node_is_not_a_leaf) {
    /*
     * The second-preimage attack, and where the defence actually lives.
     *
     * al_merkle_root takes already-hashed leaves, so at that level a 4-leaf tree
     * and a 2-"leaf" tree over its interior nodes are the same fold and produce
     * the same root. That is not a bug and the test below asserts it, because
     * pretending otherwise would hide where the real check has to happen.
     *
     * The defence is one level down, at the data-to-leaf boundary: a leaf digest
     * is tagged AL_TAG_MERKLE_LEAF and an interior node AL_TAG_MERKLE_NODE, so a
     * verifier that derives the leaf from its data with al_merkle_leaf cannot be
     * handed an interior node instead. Forging that would take a cross-tag
     * SHA-256 collision.
     */
    al_hash256 leaves[4];
    al_fill_leaves(leaves, AL_COUNTOF(leaves));

    al_hash256 root;
    al_merkle_root(leaves, 4u, &root);

    al_hash256 left, right;
    al_merkle_root(leaves, 2u, &left);
    al_merkle_root(leaves + 2, 2u, &right);

    /* Structurally identical fold - the shape carries no depth information. */
    al_hash256 interior[2] = {left, right};
    al_hash256 interior_root;
    al_merkle_root(interior, 2u, &interior_root);
    AL_CHECK(al_hash_eq(&interior_root, &root));

    /* But an interior node's digest is not in the image of al_merkle_leaf. Check
     * it against the leaf hash of its own 64-byte preimage, which is the shape a
     * forger would have to hit. */
    al_u8 preimage[64];
    memcpy(preimage, leaves[0].bytes, AL_HASH_SIZE);
    memcpy(preimage + AL_HASH_SIZE, leaves[1].bytes, AL_HASH_SIZE);

    al_hash256 as_leaf;
    al_merkle_leaf(al_bytes_make(preimage, sizeof(preimage)), &as_leaf);
    AL_CHECK(!al_hash_eq(&as_leaf, &left));
}

AL_TEST_MAIN {
    AL_RUN(leaf_hashing);
    AL_RUN(root_golden_values);
    AL_RUN(root_depends_on_order);
    AL_RUN(odd_node_is_promoted_not_duplicated);
    AL_RUN(proof_lengths);
    AL_RUN(prove_verify_roundtrip);
    AL_RUN(verify_rejects_tampering);
    AL_RUN(single_leaf_proof_is_empty);
    AL_RUN(prove_argument_validation);
    AL_RUN(interior_node_is_not_a_leaf);
}

#include "altest.h"
#include "signing_journal.h"

#include <stdio.h>

static const char *JOURNAL_PATH = "astrolune-signing-journal-test.log";

static al_pubkey test_signer(void) {
    al_u8 seed[32] = { 0u };
    seed[0] = 19u;
    al_keypair keypair;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &keypair), AL_OK);
    return keypair.pk;
}

static al_hash256 hash_text(const char *text) {
    al_hash256 hash;
    al_sha256(text, strlen(text), &hash);
    return hash;
}

AL_TEST(journal_rejects_conflicts_across_restart) {
    (void)remove(JOURNAL_PATH);
    al_pubkey signer = test_signer();
    al_hash256 first = hash_text("first decision");
    al_hash256 second = hash_text("conflicting decision");
    al_signing_journal journal = { 0 };
    AL_CHECK_EQ_STATUS(al_signing_journal_open(
                           &journal, JOURNAL_PATH, 42u, &signer),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_signing_journal_record(
                           &journal, AL_SIGNING_PROPOSAL, 7u, 2u, &first),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_signing_journal_record(
                           &journal, AL_SIGNING_PROPOSAL, 7u, 2u, &first),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_signing_journal_record(
                           &journal, AL_SIGNING_PREVOTE, 7u, 2u, &second),
                       AL_OK);
    al_signing_journal_close(&journal);

    AL_CHECK_EQ_STATUS(al_signing_journal_open(
                           &journal, JOURNAL_PATH, 42u, &signer),
                       AL_OK);
    AL_CHECK_EQ_STATUS(
        al_signing_journal_record(&journal, AL_SIGNING_PROPOSAL, 7u, 2u,
                                  &second),
        AL_ERR_CONSENSUS_VIOLATION);
    al_signing_journal_close(&journal);
    (void)remove(JOURNAL_PATH);
}

AL_TEST(journal_recovers_incomplete_tail) {
    (void)remove(JOURNAL_PATH);
    al_pubkey signer = test_signer();
    al_hash256 first = hash_text("durable decision");
    al_signing_journal journal = { 0 };
    AL_CHECK_EQ_STATUS(al_signing_journal_open(
                           &journal, JOURNAL_PATH, 42u, &signer),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_signing_journal_record(
                           &journal, AL_SIGNING_PRECOMMIT, 9u, 1u, &first),
                       AL_OK);
    al_signing_journal_close(&journal);
    FILE *file = fopen(JOURNAL_PATH, "ab");
    AL_CHECK(file != NULL);
    if (file != NULL) {
        AL_CHECK(fputc(0x5a, file) != EOF);
        AL_CHECK(fclose(file) == 0);
    }
    AL_CHECK_EQ_STATUS(al_signing_journal_open(
                           &journal, JOURNAL_PATH, 42u, &signer),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_signing_journal_record(
                           &journal, AL_SIGNING_PRECOMMIT, 9u, 1u, &first),
                       AL_OK);
    al_signing_journal_close(&journal);
    (void)remove(JOURNAL_PATH);
}

AL_TEST(journal_fails_closed_on_corruption) {
    (void)remove(JOURNAL_PATH);
    al_pubkey signer = test_signer();
    al_hash256 first = hash_text("protected decision");
    al_signing_journal journal = { 0 };
    AL_CHECK_EQ_STATUS(al_signing_journal_open(
                           &journal, JOURNAL_PATH, 42u, &signer),
                       AL_OK);
    AL_CHECK_EQ_STATUS(al_signing_journal_record(
                           &journal, AL_SIGNING_PREVOTE, 3u, 0u, &first),
                       AL_OK);
    al_signing_journal_close(&journal);
    FILE *file = fopen(JOURNAL_PATH, "r+b");
    AL_CHECK(file != NULL);
    if (file != NULL) {
        AL_CHECK(fseek(file, 24L, SEEK_SET) == 0);
        AL_CHECK(fputc(0xff, file) != EOF);
        AL_CHECK(fclose(file) == 0);
    }
    AL_CHECK_EQ_STATUS(al_signing_journal_open(
                           &journal, JOURNAL_PATH, 42u, &signer),
                       AL_ERR_STATE_CORRUPT);
    (void)remove(JOURNAL_PATH);
}

static const char *AL_TEST_SUITE_NAME = "signing_journal";

AL_TEST_MAIN {
    AL_RUN(journal_rejects_conflicts_across_restart);
    AL_RUN(journal_recovers_incomplete_tail);
    AL_RUN(journal_fails_closed_on_corruption);
}

#ifndef ASTROLUNE_DAEMON_SIGNING_JOURNAL_H
#define ASTROLUNE_DAEMON_SIGNING_JOURNAL_H

#include "finality.h"

AL_EXTERN_C_BEGIN

typedef enum al_signing_kind {
    AL_SIGNING_PROPOSAL = 1,
    AL_SIGNING_PREVOTE = 2,
    AL_SIGNING_PRECOMMIT = 3,
    AL_SIGNING_KIND_SENTINEL = 0x7fffffff
} al_signing_kind;

typedef struct al_signing_journal {
    void *impl;
} al_signing_journal;

AL_NODISCARD al_status al_signing_journal_open(
    al_signing_journal *journal, const char *path, al_u32 chain_id,
    const al_pubkey *signer);
void al_signing_journal_close(al_signing_journal *journal);

/* Persist a signing decision before producing the signature. Repeating the
 * exact decision is idempotent; a different digest for the same slot fails. */
AL_NODISCARD al_status al_signing_journal_record(
    al_signing_journal *journal, al_signing_kind kind, al_height height,
    al_u32 round, const al_hash256 *signing_hash);

AL_EXTERN_C_END

#endif

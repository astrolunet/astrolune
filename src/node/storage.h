/*
 * Durable node storage.
 *
 * Consensus sees this component only through al_state_store. State objects are
 * immutable and may be appended before a block is accepted; a state root
 * becomes canonical only when the matching block record is durably committed.
 * This ordering makes an interrupted write recover to either the previous head
 * or the complete new head, never to a root whose objects were not flushed.
 */

#ifndef ASTROLUNE_NODE_STORAGE_H
#define ASTROLUNE_NODE_STORAGE_H

#include "astrolune/block.h"
#include "finality.h"

AL_EXTERN_C_BEGIN

typedef struct al_node_storage {
    void *impl;
} al_node_storage;

/* Open or create a store rooted at directory and bind it permanently to
 * genesis. A second process cannot open the same directory concurrently. */
AL_NODISCARD al_status al_node_storage_open(
    al_node_storage *storage, const char *directory,
    const al_genesis *genesis);
void al_node_storage_close(al_node_storage *storage);

/* The returned callbacks remain valid until al_node_storage_close. Values
 * returned by value_get remain borrowed and stable for the same lifetime. */
AL_NODISCARD al_state_store al_node_storage_state_store(
    al_node_storage *storage);

/* The durable state to pass to al_state_open. With no blocks committed this is
 * the genesis initial root; head returns NULL until block zero is committed. */
AL_NODISCARD al_status al_node_storage_state_snapshot(
    const al_node_storage *storage, al_state_snapshot *out);
AL_NODISCARD const al_block_header *al_node_storage_head(
    const al_node_storage *storage);
AL_NODISCARD al_u64 al_node_storage_block_count(
    const al_node_storage *storage);
AL_NODISCARD al_u64 al_node_storage_finality_count(
    const al_node_storage *storage);

/* Commit one already validated canonical block. The state files are synced
 * before the chain record, so a successful return is the durability boundary.
 * After an error the caller must close and reopen the node before continuing. */
AL_NODISCARD al_status al_node_storage_commit_block(
    al_node_storage *storage, const al_state *state, al_bytes encoded_block);

/* Atomically advance the finalized chain. The certificate is made durable
 * before the matching block; recovery discards a certificate whose block did
 * not reach the durability boundary. */
AL_NODISCARD al_status al_node_storage_commit_finalized_block(
    al_node_storage *storage, const al_state *state, al_bytes encoded_block,
    al_bytes encoded_certificate);

/* Read a canonical block by height. written always receives the required size;
 * AL_ERR_BUFFER_TOO_SMALL leaves out untouched. */
AL_NODISCARD al_status al_node_storage_read_block(
    al_node_storage *storage, al_height height, al_bytes_mut out,
    al_size *written);
AL_NODISCARD al_status al_node_storage_read_finality(
    al_node_storage *storage, al_height height, al_bytes_mut out,
    al_size *written);

/*
 * Materialize the genesis allocation table into a fresh store.
 *
 * A genesis file commits its prefunded accounts only as a state root; the
 * tree itself must be rebuilt once from the allocation list before the state
 * can open at that root. This is a no-op once any block is committed, and it
 * fails with AL_ERR_STATE_CORRUPT when the rebuilt root disagrees with
 * genesis.initial_state_root - i.e. when the file binds a different chain
 * than it describes.
 */
AL_NODISCARD al_status al_node_storage_prepare_genesis(
    al_node_storage *storage, const al_genesis *genesis, al_arena *arena);

/*
 * Snapshot export: write a portable snapshot of the chain at the current head.
 *
 * A snapshot contains:
 *   - magic + version (for forward compatibility)
 *   - genesis hash (chain binding)
 *   - head height + state root
 *   - the encoded block at the head height
 *   - the encoded finality certificate at the head height
 *
 * The snapshot is self-contained: a new node can import it and begin syncing
 * forward from the next height without replaying the full history.
 *
 * `path` is the output file path. The file is created or overwritten.
 */
AL_NODISCARD al_status al_node_storage_export_snapshot(
    al_node_storage *storage, const char *path);

/*
 * Snapshot import: read a snapshot and prepare the store for forward sync.
 *
 * The storage must be freshly opened (no blocks committed). The function:
 *   1. Validates the snapshot (genesis match, format integrity)
 *   2. Commits the head block + finality certificate
 *   3. Positions the store at the snapshot height for forward sync
 *
 * After a successful import, `al_node_storage_block_count()` returns
 * snapshot_height + 1 and `al_node_storage_head()` returns the snapshot header.
 */
AL_NODISCARD al_status al_node_storage_import_snapshot(
    al_node_storage *storage, const al_genesis *genesis,
    al_state *state, al_arena *arena, const char *path);

/*
 * Prune: remove chain and finality records below a given height.
 *
 * After pruning, `al_node_storage_read_block()` and
 * `al_node_storage_read_finality()` return AL_ERR_NOT_FOUND for heights
 * below `keep_height`. The state remains intact at the newest committed root.
 *
 * This is irreversible: pruned data cannot be recovered without re-importing
 * a snapshot or replaying from genesis.
 *
 * `keep_height` is inclusive: records at keep_height and above are preserved.
 */
AL_NODISCARD al_status al_node_storage_prune(
    al_node_storage *storage, al_height keep_height);

AL_EXTERN_C_END

#endif /* ASTROLUNE_NODE_STORAGE_H */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif

#include "signing_journal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(AL_OS_WINDOWS)
#  include <io.h>
#else
#  include <unistd.h>
#endif

#define SIGNING_FORMAT_VERSION 1u
#define SIGNING_RECORD_SIZE    120u
#define SIGNING_PAYLOAD_SIZE   88u

static const al_u8 SIGNING_MAGIC[4] = { 'A', 'L', 'S', 'G' };

typedef struct signing_entry {
    al_signing_kind kind;
    al_height       height;
    al_u32          round;
    al_hash256      signing_hash;
} signing_entry;

typedef struct signing_journal_impl {
    FILE          *file;
    signing_entry *entries;
    al_size        count;
    al_size        capacity;
    al_u32         chain_id;
    al_pubkey      signer;
} signing_journal_impl;

static void put_u16(al_u8 *out, al_u16 value) {
    out[0] = (al_u8)(value & 0xffu);
    out[1] = (al_u8)(value >> 8u);
}

static void put_u32(al_u8 *out, al_u32 value) {
    for (al_size i = 0u; i < 4u; ++i) {
        out[i] = (al_u8)(value >> (i * 8u));
    }
}

static void put_u64(al_u8 *out, al_u64 value) {
    for (al_size i = 0u; i < 8u; ++i) {
        out[i] = (al_u8)(value >> (i * 8u));
    }
}

static al_u16 get_u16(const al_u8 *in) {
    return (al_u16)((al_u16)in[0] | ((al_u16)in[1] << 8u));
}

static al_u32 get_u32(const al_u8 *in) {
    al_u32 value = 0u;
    for (al_size i = 0u; i < 4u; ++i) {
        value |= (al_u32)in[i] << (i * 8u);
    }
    return value;
}

static al_u64 get_u64(const al_u8 *in) {
    al_u64 value = 0u;
    for (al_size i = 0u; i < 8u; ++i) {
        value |= (al_u64)in[i] << (i * 8u);
    }
    return value;
}

static al_bool signing_kind_valid(al_signing_kind kind) {
    return kind == AL_SIGNING_PROPOSAL || kind == AL_SIGNING_PREVOTE ||
                   kind == AL_SIGNING_PRECOMMIT
               ? AL_TRUE
               : AL_FALSE;
}

static al_status file_seek(FILE *file, al_u64 offset) {
    if (offset > (al_u64)INT64_MAX) return AL_ERR_OUT_OF_RANGE;
#if defined(AL_OS_WINDOWS)
    return _fseeki64(file, (__int64)offset, SEEK_SET) == 0 ? AL_OK : AL_ERR_IO;
#else
    return fseeko(file, (off_t)offset, SEEK_SET) == 0 ? AL_OK : AL_ERR_IO;
#endif
}

static al_status file_size(FILE *file, al_u64 *out) {
#if defined(AL_OS_WINDOWS)
    if (_fseeki64(file, 0, SEEK_END) != 0) return AL_ERR_IO;
    __int64 position = _ftelli64(file);
#else
    if (fseeko(file, 0, SEEK_END) != 0) return AL_ERR_IO;
    off_t position = ftello(file);
#endif
    if (position < 0) return AL_ERR_IO;
    *out = (al_u64)position;
    return AL_OK;
}

static al_status file_sync(FILE *file) {
    if (fflush(file) != 0) return AL_ERR_IO;
#if defined(AL_OS_WINDOWS)
    return _commit(_fileno(file)) == 0 ? AL_OK : AL_ERR_IO;
#else
    return fsync(fileno(file)) == 0 ? AL_OK : AL_ERR_IO;
#endif
}

static al_status file_truncate(FILE *file, al_u64 size) {
    if (fflush(file) != 0 || size > (al_u64)INT64_MAX) return AL_ERR_IO;
#if defined(AL_OS_WINDOWS)
    if (_chsize_s(_fileno(file), (__int64)size) != 0) return AL_ERR_IO;
#else
    if (ftruncate(fileno(file), (off_t)size) != 0) return AL_ERR_IO;
#endif
    AL_TRY(file_seek(file, size));
    return file_sync(file);
}

static al_status entries_prepare(signing_journal_impl *impl) {
    if (impl->count < impl->capacity) return AL_OK;
    al_size capacity = impl->capacity == 0u ? 64u : impl->capacity * 2u;
    if (capacity < impl->capacity ||
        capacity > SIZE_MAX / sizeof(*impl->entries)) {
        return AL_ERR_OUT_OF_RANGE;
    }
    signing_entry *entries = (signing_entry *)realloc(
        impl->entries, capacity * sizeof(*entries));
    if (entries == NULL) return AL_ERR_OUT_OF_MEMORY;
    impl->entries = entries;
    impl->capacity = capacity;
    return AL_OK;
}

static void encode_record(const signing_journal_impl *impl,
                          const signing_entry *entry,
                          al_u8 out[SIGNING_RECORD_SIZE]) {
    memset(out, 0, SIGNING_RECORD_SIZE);
    memcpy(out, SIGNING_MAGIC, sizeof(SIGNING_MAGIC));
    put_u16(out + 4u, SIGNING_FORMAT_VERSION);
    out[6] = (al_u8)entry->kind;
    put_u32(out + 8u, impl->chain_id);
    put_u64(out + 12u, entry->height);
    put_u32(out + 20u, entry->round);
    memcpy(out + 24u, entry->signing_hash.bytes, AL_HASH_SIZE);
    memcpy(out + 56u, impl->signer.bytes, AL_PUBKEY_SIZE);
    al_hash256 checksum;
    al_sha256(out, SIGNING_PAYLOAD_SIZE, &checksum);
    memcpy(out + SIGNING_PAYLOAD_SIZE, checksum.bytes, AL_HASH_SIZE);
}

static al_status decode_record(const signing_journal_impl *impl,
                               const al_u8 in[SIGNING_RECORD_SIZE],
                               signing_entry *out) {
    al_hash256 checksum;
    al_sha256(in, SIGNING_PAYLOAD_SIZE, &checksum);
    if (memcmp(in, SIGNING_MAGIC, sizeof(SIGNING_MAGIC)) != 0 ||
        get_u16(in + 4u) != SIGNING_FORMAT_VERSION || in[7] != 0u ||
        get_u32(in + 8u) != impl->chain_id ||
        memcmp(in + 56u, impl->signer.bytes, AL_PUBKEY_SIZE) != 0 ||
        memcmp(in + SIGNING_PAYLOAD_SIZE, checksum.bytes, AL_HASH_SIZE) != 0) {
        return AL_ERR_STATE_CORRUPT;
    }
    out->kind = (al_signing_kind)in[6];
    if (!signing_kind_valid(out->kind)) return AL_ERR_STATE_CORRUPT;
    out->height = get_u64(in + 12u);
    out->round = get_u32(in + 20u);
    memcpy(out->signing_hash.bytes, in + 24u, AL_HASH_SIZE);
    if (al_hash_is_zero(&out->signing_hash)) return AL_ERR_STATE_CORRUPT;
    return AL_OK;
}

al_status al_signing_journal_open(al_signing_journal *journal,
                                  const char *path, al_u32 chain_id,
                                  const al_pubkey *signer) {
    if (journal == NULL || journal->impl != NULL || path == NULL ||
        path[0] == '\0' || signer == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    signing_journal_impl *impl =
        (signing_journal_impl *)calloc(1u, sizeof(*impl));
    if (impl == NULL) return AL_ERR_OUT_OF_MEMORY;
    impl->chain_id = chain_id;
    impl->signer = *signer;
    impl->file = fopen(path, "r+b");
    if (impl->file == NULL && errno == ENOENT) impl->file = fopen(path, "w+b");
    if (impl->file == NULL) {
        free(impl);
        return AL_ERR_IO;
    }

    al_u64 size = 0u;
    al_status status = file_size(impl->file, &size);
    al_u64 offset = 0u;
    while (status == AL_OK && offset + SIGNING_RECORD_SIZE <= size) {
        al_u8 record[SIGNING_RECORD_SIZE];
        signing_entry entry = { 0 };
        status = file_seek(impl->file, offset);
        if (status == AL_OK &&
            fread(record, 1u, sizeof(record), impl->file) != sizeof(record)) {
            status = AL_ERR_IO;
        }
        if (status == AL_OK) status = decode_record(impl, record, &entry);
        for (al_size i = 0u; status == AL_OK && i < impl->count; ++i) {
            signing_entry *existing = &impl->entries[i];
            if (existing->kind == entry.kind &&
                existing->height == entry.height &&
                existing->round == entry.round &&
                !al_hash_eq(&existing->signing_hash, &entry.signing_hash)) {
                status = AL_ERR_STATE_CORRUPT;
            }
        }
        if (status == AL_OK) status = entries_prepare(impl);
        if (status == AL_OK) impl->entries[impl->count++] = entry;
        offset += SIGNING_RECORD_SIZE;
    }
    if (status == AL_OK && offset != size) {
        status = file_truncate(impl->file, offset);
    }
    if (status != AL_OK) {
        fclose(impl->file);
        free(impl->entries);
        free(impl);
        return status;
    }
    journal->impl = impl;
    return AL_OK;
}

void al_signing_journal_close(al_signing_journal *journal) {
    if (journal == NULL || journal->impl == NULL) return;
    signing_journal_impl *impl = (signing_journal_impl *)journal->impl;
    fclose(impl->file);
    free(impl->entries);
    free(impl);
    journal->impl = NULL;
}

al_status al_signing_journal_record(al_signing_journal *journal,
                                    al_signing_kind kind, al_height height,
                                    al_u32 round,
                                    const al_hash256 *signing_hash) {
    if (journal == NULL || journal->impl == NULL ||
        !signing_kind_valid(kind) || signing_hash == NULL ||
        al_hash_is_zero(signing_hash)) {
        return AL_ERR_INVALID_ARG;
    }
    signing_journal_impl *impl = (signing_journal_impl *)journal->impl;
    for (al_size i = 0u; i < impl->count; ++i) {
        signing_entry *entry = &impl->entries[i];
        if (entry->kind == kind && entry->height == height &&
            entry->round == round) {
            return al_hash_eq(&entry->signing_hash, signing_hash)
                       ? AL_OK
                       : AL_ERR_CONSENSUS_VIOLATION;
        }
    }

    AL_TRY(entries_prepare(impl));
    signing_entry entry = { kind, height, round, *signing_hash };
    al_u8 record[SIGNING_RECORD_SIZE];
    encode_record(impl, &entry, record);
    al_u64 offset = 0u;
    AL_TRY(file_size(impl->file, &offset));
    al_status status = fwrite(record, 1u, sizeof(record), impl->file) ==
                               sizeof(record)
                           ? file_sync(impl->file)
                           : AL_ERR_IO;
    if (status != AL_OK) {
        (void)file_truncate(impl->file, offset);
        return status;
    }
    impl->entries[impl->count++] = entry;
    return AL_OK;
}

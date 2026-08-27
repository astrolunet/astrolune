#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif

#include "storage.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(AL_OS_WINDOWS)
#  include <direct.h>
#  include <io.h>
#  include <sys/locking.h>
#else
#  include <sys/file.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#define STORAGE_FORMAT_VERSION 1u
#define STORAGE_MANIFEST_SIZE  72u
#define STORAGE_NODE_SIZE      136u
#define STORAGE_VALUE_HEADER   48u
#define STORAGE_CHAIN_HEADER   88u
#define STORAGE_FINALITY_HEADER 56u
#define STORAGE_CHECKSUM_SIZE  AL_SHA256_DIGEST_SIZE
#define STORAGE_IO_CHUNK       (64u * 1024u)

static const al_u8 MANIFEST_MAGIC[4] = { 'A', 'L', 'D', 'B' };
static const al_u8 NODE_MAGIC[4] = { 'A', 'L', 'S', 'N' };
static const al_u8 VALUE_MAGIC[4] = { 'A', 'L', 'S', 'V' };
static const al_u8 CHAIN_MAGIC[4] = { 'A', 'L', 'B', 'K' };
static const al_u8 FINALITY_MAGIC[4] = { 'A', 'L', 'F', 'C' };

typedef struct storage_index_entry {
    al_hash256 hash;
    al_u64     offset;
    al_u8     *cached_value;
    al_size    cached_size;
    al_bool    occupied;
} storage_index_entry;

typedef struct storage_index {
    storage_index_entry *entries;
    al_size              count;
    al_size              capacity;
} storage_index;

typedef struct al_node_storage_impl {
    FILE             *lock_file;
    FILE             *nodes_file;
    FILE             *values_file;
    FILE             *chain_file;
    FILE             *finality_file;
    storage_index     nodes;
    storage_index     values;
    al_u64           *block_offsets;
    al_size           block_count;
    al_size           block_capacity;
    al_u64           *finality_offsets;
    al_size           finality_count;
    al_size           finality_capacity;
    al_hash256        genesis_hash;
    al_hash256        initial_root;
    al_u32            chain_id;
    al_block_header   head;
    al_bool           has_head;
} al_node_storage_impl;

static void put_u16(al_u8 *out, al_u16 value) {
    out[0] = (al_u8)(value & 0xffu);
    out[1] = (al_u8)(value >> 8u);
}

static void put_u64(al_u8 *out, al_u64 value) {
    for (al_size i = 0u; i < 8u; ++i) {
        out[i] = (al_u8)(value >> (i * 8u));
    }
}

static al_u16 get_u16(const al_u8 *in) {
    return (al_u16)((al_u16)in[0] | ((al_u16)in[1] << 8u));
}

static al_u64 get_u64(const al_u8 *in) {
    al_u64 value = 0u;
    for (al_size i = 0u; i < 8u; ++i) {
        value |= (al_u64)in[i] << (i * 8u);
    }
    return value;
}

static al_status file_seek(FILE *file, al_u64 offset) {
#if defined(AL_OS_WINDOWS)
    if (offset > (al_u64)INT64_MAX) {
        return AL_ERR_OUT_OF_RANGE;
    }
    return _fseeki64(file, (__int64)offset, SEEK_SET) == 0 ? AL_OK : AL_ERR_IO;
#else
    if (offset > (al_u64)INT64_MAX) {
        return AL_ERR_OUT_OF_RANGE;
    }
    return fseeko(file, (off_t)offset, SEEK_SET) == 0 ? AL_OK : AL_ERR_IO;
#endif
}

static al_status file_tell(FILE *file, al_u64 *out) {
#if defined(AL_OS_WINDOWS)
    __int64 position = _ftelli64(file);
#else
    off_t position = ftello(file);
#endif
    if (position < 0) {
        return AL_ERR_IO;
    }
    *out = (al_u64)position;
    return AL_OK;
}

static al_status file_size(FILE *file, al_u64 *out) {
#if defined(AL_OS_WINDOWS)
    if (_fseeki64(file, 0, SEEK_END) != 0) {
        return AL_ERR_IO;
    }
#else
    if (fseeko(file, 0, SEEK_END) != 0) {
        return AL_ERR_IO;
    }
#endif
    return file_tell(file, out);
}

static al_status file_sync(FILE *file) {
    if (fflush(file) != 0) {
        return AL_ERR_IO;
    }
#if defined(AL_OS_WINDOWS)
    return _commit(_fileno(file)) == 0 ? AL_OK : AL_ERR_IO;
#else
    return fsync(fileno(file)) == 0 ? AL_OK : AL_ERR_IO;
#endif
}

static al_status file_truncate(FILE *file, al_u64 size) {
    if (fflush(file) != 0) {
        return AL_ERR_IO;
    }
#if defined(AL_OS_WINDOWS)
    if (size > (al_u64)INT64_MAX ||
        _chsize_s(_fileno(file), (__int64)size) != 0) {
        return AL_ERR_IO;
    }
#else
    if (size > (al_u64)INT64_MAX ||
        ftruncate(fileno(file), (off_t)size) != 0) {
        return AL_ERR_IO;
    }
#endif
    return file_seek(file, size);
}

static al_status read_exact(FILE *file, void *out, al_size size) {
    return fread(out, 1u, size, file) == size ? AL_OK : AL_ERR_IO;
}

static al_status write_exact(FILE *file, const void *data, al_size size) {
    if (size == 0u) {
        return AL_OK;
    }
    return fwrite(data, 1u, size, file) == size ? AL_OK : AL_ERR_IO;
}

static al_status checksum_region(FILE *file, al_u64 offset, al_u64 size,
                                 al_hash256 *out) {
    al_u8 buffer[STORAGE_IO_CHUNK];
    al_sha256_ctx checksum;
    al_sha256_init(&checksum);
    AL_TRY(file_seek(file, offset));

    while (size != 0u) {
        al_size chunk = size > (al_u64)sizeof(buffer)
                            ? sizeof(buffer)
                            : (al_size)size;
        AL_TRY(read_exact(file, buffer, chunk));
        al_sha256_update(&checksum, buffer, chunk);
        size -= chunk;
    }
    al_sha256_final(&checksum, out);
    return AL_OK;
}

static al_status make_directory_part(const char *path) {
#if defined(AL_OS_WINDOWS)
    int result = _mkdir(path);
#else
    int result = mkdir(path, 0755);
#endif
    return result == 0 || errno == EEXIST ? AL_OK : AL_ERR_IO;
}

static al_bool path_separator(char value) {
    return value == '/' || value == '\\' ? AL_TRUE : AL_FALSE;
}

static al_status ensure_directory(const char *directory) {
    if (directory == NULL || directory[0] == '\0') {
        return AL_ERR_INVALID_ARG;
    }
    al_size length = strlen(directory);
    if (length == 0u || length == SIZE_MAX) {
        return AL_ERR_OUT_OF_RANGE;
    }

    char *path = (char *)malloc(length + 1u);
    if (path == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    memcpy(path, directory, length + 1u);

    al_size separators = 0u;
    for (al_size i = 0u; i < length; ++i) {
        if (!path_separator(path[i])) {
            continue;
        }
        ++separators;
        if (i == 0u || (i == 2u && path[1] == ':') ||
            (path_separator(path[0]) && path_separator(path[1]) &&
             separators <= 3u)) {
            continue;
        }
        char separator = path[i];
        path[i] = '\0';
        al_status status = make_directory_part(path);
        path[i] = separator;
        if (status != AL_OK) {
            free(path);
            return status;
        }
    }
    al_status status = make_directory_part(path);
    free(path);
    return status;
}

static al_status join_path(const char *directory, const char *name,
                           char **out) {
    al_size directory_size = strlen(directory);
    al_size name_size = strlen(name);
    al_bool needs_separator =
        directory_size != 0u && !path_separator(directory[directory_size - 1u]);
    al_size extra = needs_separator ? 2u : 1u;
    if (directory_size > SIZE_MAX - name_size - extra) {
        return AL_ERR_OUT_OF_RANGE;
    }

    char *path = (char *)malloc(directory_size + name_size + extra);
    if (path == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    memcpy(path, directory, directory_size);
    al_size position = directory_size;
    if (needs_separator) {
        path[position++] = '/';
    }
    memcpy(path + position, name, name_size + 1u);
    *out = path;
    return AL_OK;
}

static al_status open_file(const char *directory, const char *name,
                           FILE **out) {
    char *path = NULL;
    AL_TRY(join_path(directory, name, &path));
    FILE *file = fopen(path, "r+b");
    if (file == NULL && errno == ENOENT) {
        file = fopen(path, "w+b");
    }
    free(path);
    if (file == NULL) {
        return AL_ERR_IO;
    }
    *out = file;
    return AL_OK;
}

static al_status lock_store(FILE *file) {
    al_u64 size = 0u;
    AL_TRY(file_size(file, &size));
    if (size == 0u) {
        const al_u8 marker = 0u;
        AL_TRY(write_exact(file, &marker, sizeof(marker)));
        AL_TRY(file_sync(file));
    }
    AL_TRY(file_seek(file, 0u));
#if defined(AL_OS_WINDOWS)
    return _locking(_fileno(file), _LK_NBLCK, 1L) == 0 ? AL_OK : AL_ERR_IO;
#else
    return flock(fileno(file), LOCK_EX | LOCK_NB) == 0 ? AL_OK : AL_ERR_IO;
#endif
}

static void unlock_store(FILE *file) {
    if (file == NULL) {
        return;
    }
#if defined(AL_OS_WINDOWS)
    (void)file_seek(file, 0u);
    (void)_locking(_fileno(file), _LK_UNLCK, 1L);
#else
    (void)flock(fileno(file), LOCK_UN);
#endif
}

static al_size index_slot(const al_hash256 *hash, al_size capacity) {
    al_u64 value = get_u64(hash->bytes);
    value ^= value >> 33u;
    value *= UINT64_C(0xff51afd7ed558ccd);
    value ^= value >> 33u;
    return (al_size)(value & (al_u64)(capacity - 1u));
}

static storage_index_entry *index_find(storage_index *index,
                                       const al_hash256 *hash) {
    if (index->capacity == 0u) {
        return NULL;
    }
    al_size slot = index_slot(hash, index->capacity);
    for (;;) {
        storage_index_entry *entry = &index->entries[slot];
        if (!entry->occupied) {
            return NULL;
        }
        if (al_hash_eq(&entry->hash, hash)) {
            return entry;
        }
        slot = (slot + 1u) & (index->capacity - 1u);
    }
}

static al_status index_reserve(storage_index *index, al_size capacity) {
    storage_index_entry *entries = (storage_index_entry *)calloc(
        capacity, sizeof(*entries));
    if (entries == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }

    for (al_size i = 0u; i < index->capacity; ++i) {
        storage_index_entry old = index->entries[i];
        if (!old.occupied) {
            continue;
        }
        al_size slot = index_slot(&old.hash, capacity);
        while (entries[slot].occupied) {
            slot = (slot + 1u) & (capacity - 1u);
        }
        entries[slot] = old;
    }
    free(index->entries);
    index->entries = entries;
    index->capacity = capacity;
    return AL_OK;
}

static al_status index_prepare_insert(storage_index *index) {
    if (index->capacity == 0u) {
        return index_reserve(index, 1024u);
    }
    if (index->count < index->capacity - index->capacity / 4u) {
        return AL_OK;
    }
    if (index->capacity > SIZE_MAX / 2u) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    return index_reserve(index, index->capacity * 2u);
}

static al_status index_insert(storage_index *index, const al_hash256 *hash,
                              al_u64 offset, storage_index_entry **out) {
    if (index_find(index, hash) != NULL) {
        return AL_ERR_ALREADY_EXISTS;
    }
    AL_TRY(index_prepare_insert(index));

    al_size slot = index_slot(hash, index->capacity);
    while (index->entries[slot].occupied) {
        slot = (slot + 1u) & (index->capacity - 1u);
    }
    storage_index_entry *entry = &index->entries[slot];
    entry->hash = *hash;
    entry->offset = offset;
    entry->occupied = AL_TRUE;
    ++index->count;
    if (out != NULL) {
        *out = entry;
    }
    return AL_OK;
}

static void index_destroy(storage_index *index, al_bool free_values) {
    if (free_values) {
        for (al_size i = 0u; i < index->capacity; ++i) {
            free(index->entries[i].cached_value);
        }
    }
    free(index->entries);
    memset(index, 0, sizeof(*index));
}

static void node_hash(const al_state_node *node, al_hash256 *out) {
    const char *tag = node->kind == AL_STATE_NODE_BRANCH
                          ? AL_TAG_SMT_NODE
                          : AL_TAG_SMT_LEAF;
    al_hash_tagged_pair(tag, &node->first, &node->second, out);
}

static al_status decode_node_record(const al_u8 record[STORAGE_NODE_SIZE],
                                    al_hash256 *hash, al_state_node *node) {
    if (memcmp(record, NODE_MAGIC, sizeof(NODE_MAGIC)) != 0 ||
        get_u16(record + 4u) != STORAGE_FORMAT_VERSION) {
        return AL_ERR_STATE_CORRUPT;
    }
    al_u16 kind = get_u16(record + 6u);
    if (kind != (al_u16)AL_STATE_NODE_BRANCH &&
        kind != (al_u16)AL_STATE_NODE_LEAF) {
        return AL_ERR_STATE_CORRUPT;
    }

    al_hash256 expected;
    al_sha256(record, STORAGE_NODE_SIZE - STORAGE_CHECKSUM_SIZE, &expected);
    if (memcmp(expected.bytes,
               record + STORAGE_NODE_SIZE - STORAGE_CHECKSUM_SIZE,
               STORAGE_CHECKSUM_SIZE) != 0) {
        return AL_ERR_TRUNCATED;
    }

    memcpy(hash->bytes, record + 8u, AL_HASH_SIZE);
    node->kind = (al_state_node_kind)kind;
    memcpy(node->first.bytes, record + 40u, AL_HASH_SIZE);
    memcpy(node->second.bytes, record + 72u, AL_HASH_SIZE);
    al_hash256 actual;
    node_hash(node, &actual);
    return al_hash_eq(hash, &actual) ? AL_OK : AL_ERR_STATE_CORRUPT;
}

static al_status scan_nodes(al_node_storage_impl *impl) {
    al_u64 size = 0u;
    AL_TRY(file_size(impl->nodes_file, &size));
    al_u64 offset = 0u;
    while (offset < size) {
        if (size - offset < STORAGE_NODE_SIZE) {
            AL_TRY(file_truncate(impl->nodes_file, offset));
            break;
        }
        al_u8 record[STORAGE_NODE_SIZE];
        AL_TRY(file_seek(impl->nodes_file, offset));
        AL_TRY(read_exact(impl->nodes_file, record, sizeof(record)));
        al_hash256 hash;
        al_state_node node;
        al_status status = decode_node_record(record, &hash, &node);
        if (status == AL_ERR_TRUNCATED && offset + STORAGE_NODE_SIZE == size) {
            AL_TRY(file_truncate(impl->nodes_file, offset));
            break;
        }
        if (status != AL_OK) {
            return AL_ERR_STATE_CORRUPT;
        }
        status = index_insert(&impl->nodes, &hash, offset, NULL);
        if (status != AL_OK) {
            return status == AL_ERR_ALREADY_EXISTS
                       ? AL_ERR_STATE_CORRUPT
                       : status;
        }
        offset += STORAGE_NODE_SIZE;
    }
    return file_seek(impl->nodes_file, offset);
}

static al_status value_record_info(FILE *file, al_u64 offset,
                                   al_hash256 *hash, al_u64 *value_size) {
    al_u8 header[STORAGE_VALUE_HEADER];
    AL_TRY(file_seek(file, offset));
    AL_TRY(read_exact(file, header, sizeof(header)));
    if (memcmp(header, VALUE_MAGIC, sizeof(VALUE_MAGIC)) != 0 ||
        get_u16(header + 4u) != STORAGE_FORMAT_VERSION ||
        get_u16(header + 6u) != 0u) {
        return AL_ERR_STATE_CORRUPT;
    }
    memcpy(hash->bytes, header + 8u, AL_HASH_SIZE);
    *value_size = get_u64(header + 40u);
    if (*value_size > AL_STATE_MAX_CODE_SIZE) {
        return AL_ERR_STATE_CORRUPT;
    }
    return AL_OK;
}

static al_status scan_values(al_node_storage_impl *impl) {
    al_u64 size = 0u;
    AL_TRY(file_size(impl->values_file, &size));
    al_u64 offset = 0u;
    while (offset < size) {
        if (size - offset < STORAGE_VALUE_HEADER + STORAGE_CHECKSUM_SIZE) {
            AL_TRY(file_truncate(impl->values_file, offset));
            break;
        }
        al_hash256 hash;
        al_u64 value_size = 0u;
        AL_TRY(value_record_info(impl->values_file, offset, &hash, &value_size));
        al_u64 record_size = STORAGE_VALUE_HEADER + value_size +
                             STORAGE_CHECKSUM_SIZE;
        if (record_size > size - offset) {
            AL_TRY(file_truncate(impl->values_file, offset));
            break;
        }

        al_hash256 actual;
        AL_TRY(checksum_region(impl->values_file, offset,
                               STORAGE_VALUE_HEADER + value_size, &actual));
        al_hash256 stored;
        AL_TRY(read_exact(impl->values_file, stored.bytes, AL_HASH_SIZE));
        if (!al_hash_eq(&actual, &stored)) {
            if (offset + record_size == size) {
                AL_TRY(file_truncate(impl->values_file, offset));
                break;
            }
            return AL_ERR_STATE_CORRUPT;
        }
        al_status status = index_insert(
            &impl->values, &hash, offset, NULL);
        if (status != AL_OK) {
            return status == AL_ERR_ALREADY_EXISTS
                       ? AL_ERR_STATE_CORRUPT
                       : status;
        }
        offset += record_size;
    }
    return file_seek(impl->values_file, offset);
}

static al_status disk_node_get(void *context, const al_hash256 *hash,
                               al_state_node *out) {
    al_node_storage_impl *impl = (al_node_storage_impl *)context;
    if (impl == NULL || hash == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    storage_index_entry *entry = index_find(&impl->nodes, hash);
    if (entry == NULL) {
        return AL_ERR_NOT_FOUND;
    }

    al_u8 record[STORAGE_NODE_SIZE];
    AL_TRY(file_seek(impl->nodes_file, entry->offset));
    AL_TRY(read_exact(impl->nodes_file, record, sizeof(record)));
    al_hash256 stored_hash;
    AL_TRY(decode_node_record(record, &stored_hash, out));
    return al_hash_eq(hash, &stored_hash) ? AL_OK : AL_ERR_STATE_CORRUPT;
}

static al_status disk_node_put(void *context, const al_hash256 *hash,
                               const al_state_node *node) {
    al_node_storage_impl *impl = (al_node_storage_impl *)context;
    if (impl == NULL || hash == NULL || node == NULL ||
        (node->kind != AL_STATE_NODE_BRANCH &&
         node->kind != AL_STATE_NODE_LEAF)) {
        return AL_ERR_INVALID_ARG;
    }
    al_hash256 actual;
    node_hash(node, &actual);
    if (!al_hash_eq(hash, &actual)) {
        return AL_ERR_STATE_CORRUPT;
    }

    storage_index_entry *existing = index_find(&impl->nodes, hash);
    if (existing != NULL) {
        al_state_node stored;
        AL_TRY(disk_node_get(context, hash, &stored));
        return stored.kind == node->kind &&
                       al_hash_eq(&stored.first, &node->first) &&
                       al_hash_eq(&stored.second, &node->second)
                   ? AL_OK
                   : AL_ERR_STATE_CORRUPT;
    }
    AL_TRY(index_prepare_insert(&impl->nodes));

    al_u8 record[STORAGE_NODE_SIZE];
    memset(record, 0, sizeof(record));
    memcpy(record, NODE_MAGIC, sizeof(NODE_MAGIC));
    put_u16(record + 4u, STORAGE_FORMAT_VERSION);
    put_u16(record + 6u, (al_u16)node->kind);
    memcpy(record + 8u, hash->bytes, AL_HASH_SIZE);
    memcpy(record + 40u, node->first.bytes, AL_HASH_SIZE);
    memcpy(record + 72u, node->second.bytes, AL_HASH_SIZE);
    al_hash256 checksum;
    al_sha256(record, STORAGE_NODE_SIZE - STORAGE_CHECKSUM_SIZE, &checksum);
    memcpy(record + STORAGE_NODE_SIZE - STORAGE_CHECKSUM_SIZE,
           checksum.bytes, AL_HASH_SIZE);

    al_u64 offset = 0u;
    AL_TRY(file_size(impl->nodes_file, &offset));
    al_status status = write_exact(impl->nodes_file, record, sizeof(record));
    if (status != AL_OK) {
        (void)file_truncate(impl->nodes_file, offset);
        return status;
    }
    return index_insert(&impl->nodes, hash, offset, NULL);
}

static al_status load_cached_value(al_node_storage_impl *impl,
                                   storage_index_entry *entry) {
    if (entry->cached_value != NULL || entry->cached_size != 0u) {
        return AL_OK;
    }
    al_hash256 hash;
    al_u64 value_size = 0u;
    AL_TRY(value_record_info(impl->values_file, entry->offset, &hash,
                             &value_size));
    if (!al_hash_eq(&hash, &entry->hash) || value_size > (al_u64)SIZE_MAX) {
        return AL_ERR_STATE_CORRUPT;
    }

    al_size size = (al_size)value_size;
    al_u8 *value = NULL;
    if (size != 0u) {
        value = (al_u8 *)malloc(size);
        if (value == NULL) {
            return AL_ERR_OUT_OF_MEMORY;
        }
        al_status status = read_exact(impl->values_file, value, size);
        if (status != AL_OK) {
            free(value);
            return status;
        }
    }
    entry->cached_value = value;
    entry->cached_size = size;
    return AL_OK;
}

static al_status disk_value_get(void *context, const al_hash256 *hash,
                                al_bytes *out) {
    al_node_storage_impl *impl = (al_node_storage_impl *)context;
    if (impl == NULL || hash == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    storage_index_entry *entry = index_find(&impl->values, hash);
    if (entry == NULL) {
        return AL_ERR_NOT_FOUND;
    }
    AL_TRY(load_cached_value(impl, entry));
    *out = al_bytes_make(entry->cached_value, entry->cached_size);
    return AL_OK;
}

static al_status disk_value_put(void *context, const al_hash256 *hash,
                                al_bytes value) {
    al_node_storage_impl *impl = (al_node_storage_impl *)context;
    if (impl == NULL || hash == NULL ||
        (value.data == NULL && value.len != 0u) ||
        value.len > AL_STATE_MAX_CODE_SIZE) {
        return AL_ERR_INVALID_ARG;
    }
    storage_index_entry *existing = index_find(&impl->values, hash);
    if (existing != NULL) {
        al_bytes stored;
        AL_TRY(disk_value_get(context, hash, &stored));
        return al_bytes_eq(stored, value) ? AL_OK : AL_ERR_STATE_CORRUPT;
    }
    AL_TRY(index_prepare_insert(&impl->values));

    al_u8 header[STORAGE_VALUE_HEADER];
    memset(header, 0, sizeof(header));
    memcpy(header, VALUE_MAGIC, sizeof(VALUE_MAGIC));
    put_u16(header + 4u, STORAGE_FORMAT_VERSION);
    memcpy(header + 8u, hash->bytes, AL_HASH_SIZE);
    put_u64(header + 40u, (al_u64)value.len);

    al_sha256_ctx checksum_context;
    al_hash256 checksum;
    al_sha256_init(&checksum_context);
    al_sha256_update(&checksum_context, header, sizeof(header));
    al_sha256_update(&checksum_context, value.data, value.len);
    al_sha256_final(&checksum_context, &checksum);

    al_u64 offset = 0u;
    AL_TRY(file_size(impl->values_file, &offset));
    al_status status = write_exact(impl->values_file, header, sizeof(header));
    if (status == AL_OK) {
        status = write_exact(impl->values_file, value.data, value.len);
    }
    if (status == AL_OK) {
        status = write_exact(impl->values_file, checksum.bytes, AL_HASH_SIZE);
    }
    if (status != AL_OK) {
        (void)file_truncate(impl->values_file, offset);
        return status;
    }

    storage_index_entry *entry = NULL;
    AL_TRY(index_insert(&impl->values, hash, offset, &entry));
    if (value.len != 0u) {
        entry->cached_value = (al_u8 *)malloc(value.len);
        if (entry->cached_value != NULL) {
            memcpy(entry->cached_value, value.data, value.len);
            entry->cached_size = value.len;
        }
    }
    return AL_OK;
}

static al_status manifest_open(al_node_storage_impl *impl, FILE *manifest) {
    al_u64 size = 0u;
    AL_TRY(file_size(manifest, &size));
    if (size == 0u) {
        al_u8 encoded[STORAGE_MANIFEST_SIZE];
        memset(encoded, 0, sizeof(encoded));
        memcpy(encoded, MANIFEST_MAGIC, sizeof(MANIFEST_MAGIC));
        put_u16(encoded + 4u, STORAGE_FORMAT_VERSION);
        memcpy(encoded + 8u, impl->genesis_hash.bytes, AL_HASH_SIZE);
        al_hash256 checksum;
        al_sha256(encoded, STORAGE_MANIFEST_SIZE - STORAGE_CHECKSUM_SIZE,
                  &checksum);
        memcpy(encoded + STORAGE_MANIFEST_SIZE - STORAGE_CHECKSUM_SIZE,
               checksum.bytes, AL_HASH_SIZE);
        AL_TRY(file_seek(manifest, 0u));
        AL_TRY(write_exact(manifest, encoded, sizeof(encoded)));
        return file_sync(manifest);
    }
    if (size != STORAGE_MANIFEST_SIZE) {
        return AL_ERR_STATE_CORRUPT;
    }

    al_u8 encoded[STORAGE_MANIFEST_SIZE];
    AL_TRY(file_seek(manifest, 0u));
    AL_TRY(read_exact(manifest, encoded, sizeof(encoded)));
    al_hash256 checksum;
    al_sha256(encoded, STORAGE_MANIFEST_SIZE - STORAGE_CHECKSUM_SIZE,
              &checksum);
    if (memcmp(encoded, MANIFEST_MAGIC, sizeof(MANIFEST_MAGIC)) != 0 ||
        get_u16(encoded + 4u) != STORAGE_FORMAT_VERSION ||
        get_u16(encoded + 6u) != 0u ||
        memcmp(encoded + 8u, impl->genesis_hash.bytes, AL_HASH_SIZE) != 0 ||
        memcmp(encoded + STORAGE_MANIFEST_SIZE - STORAGE_CHECKSUM_SIZE,
               checksum.bytes, AL_HASH_SIZE) != 0) {
        return AL_ERR_STATE_CORRUPT;
    }
    return AL_OK;
}

static al_status block_offsets_prepare(al_node_storage_impl *impl) {
    if (impl->block_count < impl->block_capacity) {
        return AL_OK;
    }
    al_size capacity = impl->block_capacity == 0u
                           ? 1024u
                           : impl->block_capacity * 2u;
    if (capacity < impl->block_capacity ||
        capacity > SIZE_MAX / sizeof(*impl->block_offsets)) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_u64 *offsets = (al_u64 *)realloc(
        impl->block_offsets, capacity * sizeof(*offsets));
    if (offsets == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    impl->block_offsets = offsets;
    impl->block_capacity = capacity;
    return AL_OK;
}

static al_status block_offsets_append(al_node_storage_impl *impl,
                                      al_u64 offset) {
    AL_TRY(block_offsets_prepare(impl));
    impl->block_offsets[impl->block_count++] = offset;
    return AL_OK;
}

static al_status finality_offsets_prepare(al_node_storage_impl *impl) {
    if (impl->finality_count < impl->finality_capacity) return AL_OK;
    al_size capacity = impl->finality_capacity == 0u
                           ? 1024u
                           : impl->finality_capacity * 2u;
    if (capacity < impl->finality_capacity ||
        capacity > SIZE_MAX / sizeof(*impl->finality_offsets)) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_u64 *offsets = (al_u64 *)realloc(
        impl->finality_offsets, capacity * sizeof(*offsets));
    if (offsets == NULL) return AL_ERR_OUT_OF_MEMORY;
    impl->finality_offsets = offsets;
    impl->finality_capacity = capacity;
    return AL_OK;
}

static al_status finality_offsets_append(al_node_storage_impl *impl,
                                         al_u64 offset) {
    AL_TRY(finality_offsets_prepare(impl));
    impl->finality_offsets[impl->finality_count++] = offset;
    return AL_OK;
}

static al_status chain_record_header(
    FILE *file, al_u64 offset, al_u8 header[STORAGE_CHAIN_HEADER],
    al_u64 *payload_size) {
    AL_TRY(file_seek(file, offset));
    AL_TRY(read_exact(file, header, STORAGE_CHAIN_HEADER));
    if (memcmp(header, CHAIN_MAGIC, sizeof(CHAIN_MAGIC)) != 0 ||
        get_u16(header + 4u) != STORAGE_FORMAT_VERSION ||
        get_u16(header + 6u) != 0u) {
        return AL_ERR_STATE_CORRUPT;
    }
    *payload_size = get_u64(header + 80u);
    return AL_OK;
}

static al_status finality_record_header(
    FILE *file, al_u64 offset, al_u8 header[STORAGE_FINALITY_HEADER],
    al_u64 *payload_size) {
    AL_TRY(file_seek(file, offset));
    AL_TRY(read_exact(file, header, STORAGE_FINALITY_HEADER));
    if (memcmp(header, FINALITY_MAGIC, sizeof(FINALITY_MAGIC)) != 0 ||
        get_u16(header + 4u) != STORAGE_FORMAT_VERSION ||
        get_u16(header + 6u) != 0u) {
        return AL_ERR_STATE_CORRUPT;
    }
    *payload_size = get_u64(header + 48u);
    return AL_OK;
}

static al_status decode_stored_header(FILE *file, al_u64 payload_offset,
                                      al_u64 payload_size,
                                      al_block_header *out) {
    if (payload_size < AL_BLOCK_HEADER_ENCODED_SIZE) {
        return AL_ERR_STATE_CORRUPT;
    }
    al_u8 encoded[AL_BLOCK_HEADER_ENCODED_SIZE];
    AL_TRY(file_seek(file, payload_offset));
    AL_TRY(read_exact(file, encoded, sizeof(encoded)));
    al_status status = al_block_header_decode(
        al_bytes_make(encoded, sizeof(encoded)), out);
    return status == AL_OK ? AL_OK : AL_ERR_STATE_CORRUPT;
}

static al_status scan_chain(al_node_storage_impl *impl) {
    al_u64 size = 0u;
    AL_TRY(file_size(impl->chain_file, &size));
    al_u64 offset = 0u;
    while (offset < size) {
        if (size - offset < STORAGE_CHAIN_HEADER + STORAGE_CHECKSUM_SIZE) {
            AL_TRY(file_truncate(impl->chain_file, offset));
            break;
        }
        al_u8 record_header[STORAGE_CHAIN_HEADER];
        al_u64 payload_size = 0u;
        AL_TRY(chain_record_header(impl->chain_file, offset, record_header,
                                   &payload_size));
        if (payload_size > UINT64_MAX - STORAGE_CHAIN_HEADER -
                               STORAGE_CHECKSUM_SIZE) {
            return AL_ERR_STATE_CORRUPT;
        }
        al_u64 record_size = STORAGE_CHAIN_HEADER + payload_size +
                             STORAGE_CHECKSUM_SIZE;
        if (record_size > size - offset) {
            AL_TRY(file_truncate(impl->chain_file, offset));
            break;
        }

        al_hash256 actual_checksum;
        AL_TRY(checksum_region(impl->chain_file, offset,
                               STORAGE_CHAIN_HEADER + payload_size,
                               &actual_checksum));
        al_hash256 stored_checksum;
        AL_TRY(read_exact(impl->chain_file, stored_checksum.bytes,
                          AL_HASH_SIZE));
        if (!al_hash_eq(&actual_checksum, &stored_checksum)) {
            if (offset + record_size == size) {
                AL_TRY(file_truncate(impl->chain_file, offset));
                break;
            }
            return AL_ERR_STATE_CORRUPT;
        }

        al_block_header header;
        AL_TRY(decode_stored_header(impl->chain_file,
                                    offset + STORAGE_CHAIN_HEADER,
                                    payload_size, &header));
        al_hash256 block_hash;
        al_block_header_hash(&header, &block_hash);
        al_u64 stored_height = get_u64(record_header + 8u);
        if (stored_height != (al_u64)impl->block_count ||
            header.version != AL_BLOCK_VERSION ||
            header.chain_id != impl->chain_id ||
            header.height != stored_height ||
            memcmp(record_header + 16u, block_hash.bytes, AL_HASH_SIZE) != 0 ||
            memcmp(record_header + 48u, header.state_root.bytes,
                   AL_HASH_SIZE) != 0) {
            return AL_ERR_STATE_CORRUPT;
        }
        if (impl->has_head) {
            al_hash256 parent_hash;
            al_block_header_hash(&impl->head, &parent_hash);
            if (!al_hash_eq(&header.parent_hash, &parent_hash)) {
                return AL_ERR_STATE_CORRUPT;
            }
        } else if (!al_hash_is_zero(&header.parent_hash)) {
            return AL_ERR_STATE_CORRUPT;
        }

        AL_TRY(block_offsets_append(impl, offset));
        impl->head = header;
        impl->has_head = AL_TRUE;
        offset += record_size;
    }
    return file_seek(impl->chain_file, offset);
}

static al_status scan_finality(al_node_storage_impl *impl) {
    al_u64 size = 0u;
    AL_TRY(file_size(impl->finality_file, &size));
    al_u8 *encoded = (al_u8 *)malloc(
        AL_FINALITY_CERTIFICATE_MAX_ENCODED_SIZE);
    al_finality_certificate *certificate =
        (al_finality_certificate *)malloc(sizeof(*certificate));
    if (encoded == NULL || certificate == NULL) {
        free(encoded);
        free(certificate);
        return AL_ERR_OUT_OF_MEMORY;
    }

    al_status status = AL_OK;
    al_u64 offset = 0u;
    while (offset < size) {
        if (impl->finality_count >= impl->block_count) {
            status = file_truncate(impl->finality_file, offset);
            break;
        }
        if (size - offset < STORAGE_FINALITY_HEADER + STORAGE_CHECKSUM_SIZE) {
            status = file_truncate(impl->finality_file, offset);
            break;
        }
        al_u8 record_header[STORAGE_FINALITY_HEADER];
        al_u64 payload_size = 0u;
        status = finality_record_header(impl->finality_file, offset,
                                        record_header, &payload_size);
        if (status != AL_OK) break;
        if (payload_size == 0u ||
            payload_size > AL_FINALITY_CERTIFICATE_MAX_ENCODED_SIZE ||
            payload_size > UINT64_MAX - STORAGE_FINALITY_HEADER -
                               STORAGE_CHECKSUM_SIZE) {
            status = AL_ERR_STATE_CORRUPT;
            break;
        }
        al_u64 record_size = STORAGE_FINALITY_HEADER + payload_size +
                             STORAGE_CHECKSUM_SIZE;
        if (record_size > size - offset) {
            status = file_truncate(impl->finality_file, offset);
            break;
        }

        al_hash256 actual_checksum;
        status = checksum_region(impl->finality_file, offset,
                                 STORAGE_FINALITY_HEADER + payload_size,
                                 &actual_checksum);
        if (status != AL_OK) break;
        al_hash256 stored_checksum;
        status = read_exact(impl->finality_file, stored_checksum.bytes,
                            AL_HASH_SIZE);
        if (status != AL_OK) break;
        if (!al_hash_eq(&actual_checksum, &stored_checksum)) {
            if (offset + record_size == size) {
                status = file_truncate(impl->finality_file, offset);
                break;
            }
            status = AL_ERR_STATE_CORRUPT;
            break;
        }

        status = file_seek(impl->finality_file,
                           offset + STORAGE_FINALITY_HEADER);
        if (status == AL_OK) {
            status = read_exact(impl->finality_file, encoded,
                                (al_size)payload_size);
        }
        if (status == AL_OK) {
            status = al_finality_certificate_decode(
                al_bytes_make(encoded, (al_size)payload_size), certificate);
        }
        al_height height = (al_height)impl->finality_count;
        al_block_header block_header;
        al_hash256 block_hash;
        if (status == AL_OK) {
            status = decode_stored_header(
                impl->chain_file,
                impl->block_offsets[impl->finality_count] +
                    STORAGE_CHAIN_HEADER,
                AL_BLOCK_HEADER_ENCODED_SIZE, &block_header);
        }
        if (status == AL_OK) {
            al_block_header_hash(&block_header, &block_hash);
            if (get_u64(record_header + 8u) != height ||
                certificate->chain_id != impl->chain_id ||
                certificate->height != height ||
                !al_hash_eq(&certificate->block_hash, &block_hash) ||
                memcmp(record_header + 16u, block_hash.bytes,
                       AL_HASH_SIZE) != 0) {
                status = AL_ERR_STATE_CORRUPT;
            }
        }
        if (status != AL_OK) break;
        status = finality_offsets_append(impl, offset);
        if (status != AL_OK) break;
        offset += record_size;
    }
    if (status == AL_OK) status = file_seek(impl->finality_file, offset);
    free(certificate);
    free(encoded);
    return status;
}

static void storage_impl_destroy(al_node_storage_impl *impl) {
    if (impl == NULL) {
        return;
    }
    if (impl->nodes_file != NULL) {
        (void)fclose(impl->nodes_file);
    }
    if (impl->values_file != NULL) {
        (void)fclose(impl->values_file);
    }
    if (impl->chain_file != NULL) {
        (void)fclose(impl->chain_file);
    }
    if (impl->finality_file != NULL) {
        (void)fclose(impl->finality_file);
    }
    unlock_store(impl->lock_file);
    if (impl->lock_file != NULL) {
        (void)fclose(impl->lock_file);
    }
    index_destroy(&impl->nodes, AL_FALSE);
    index_destroy(&impl->values, AL_TRUE);
    free(impl->block_offsets);
    free(impl->finality_offsets);
    free(impl);
}

al_status al_node_storage_open(al_node_storage *storage,
                               const char *directory,
                               const al_genesis *genesis) {
    if (storage == NULL || directory == NULL || genesis == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    storage->impl = NULL;
    AL_TRY(al_genesis_validate(genesis));
    AL_TRY(ensure_directory(directory));

    al_node_storage_impl *impl =
        (al_node_storage_impl *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    al_genesis_hash(genesis, &impl->genesis_hash);
    impl->initial_root = genesis->initial_state_root;
    impl->chain_id = genesis->chain_id;

    FILE *manifest = NULL;
    al_status status = open_file(directory, "LOCK", &impl->lock_file);
    if (status == AL_OK) {
        status = lock_store(impl->lock_file);
    }
    if (status == AL_OK) {
        status = open_file(directory, "manifest.bin", &manifest);
    }
    if (status == AL_OK) {
        status = manifest_open(impl, manifest);
    }
    if (manifest != NULL && fclose(manifest) != 0 && status == AL_OK) {
        status = AL_ERR_IO;
    }
    if (status == AL_OK) {
        status = open_file(directory, "state-nodes.log", &impl->nodes_file);
    }
    if (status == AL_OK) {
        status = open_file(directory, "state-values.log", &impl->values_file);
    }
    if (status == AL_OK) {
        status = open_file(directory, "chain.log", &impl->chain_file);
    }
    if (status == AL_OK) {
        status = open_file(directory, "finality.log", &impl->finality_file);
    }
    if (status == AL_OK) {
        status = scan_nodes(impl);
    }
    if (status == AL_OK) {
        status = scan_values(impl);
    }
    if (status == AL_OK) {
        status = scan_chain(impl);
    }
    if (status == AL_OK) {
        status = scan_finality(impl);
    }
    if (status != AL_OK) {
        storage_impl_destroy(impl);
        return status;
    }

    storage->impl = impl;
    return AL_OK;
}

void al_node_storage_close(al_node_storage *storage) {
    if (storage == NULL) {
        return;
    }
    storage_impl_destroy((al_node_storage_impl *)storage->impl);
    storage->impl = NULL;
}

al_state_store al_node_storage_state_store(al_node_storage *storage) {
    al_state_store store;
    memset(&store, 0, sizeof(store));
    if (storage == NULL || storage->impl == NULL) {
        return store;
    }
    store.context = storage->impl;
    store.node_get = disk_node_get;
    store.node_put = disk_node_put;
    store.value_get = disk_value_get;
    store.value_put = disk_value_put;
    return store;
}

al_status al_node_storage_state_snapshot(const al_node_storage *storage,
                                         al_state_snapshot *out) {
    if (storage == NULL || storage->impl == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    const al_node_storage_impl *impl =
        (const al_node_storage_impl *)storage->impl;
    if (impl->has_head) {
        out->height = impl->head.height;
        out->root = impl->head.state_root;
    } else {
        out->height = 0u;
        out->root = impl->initial_root;
    }
    return AL_OK;
}

const al_block_header *al_node_storage_head(const al_node_storage *storage) {
    if (storage == NULL || storage->impl == NULL) {
        return NULL;
    }
    const al_node_storage_impl *impl =
        (const al_node_storage_impl *)storage->impl;
    return impl->has_head ? &impl->head : NULL;
}

al_u64 al_node_storage_block_count(const al_node_storage *storage) {
    if (storage == NULL || storage->impl == NULL) {
        return 0u;
    }
    const al_node_storage_impl *impl =
        (const al_node_storage_impl *)storage->impl;
    return (al_u64)impl->block_count;
}

al_u64 al_node_storage_finality_count(const al_node_storage *storage) {
    if (storage == NULL || storage->impl == NULL) return 0u;
    const al_node_storage_impl *impl =
        (const al_node_storage_impl *)storage->impl;
    return (al_u64)impl->finality_count;
}

static al_status sync_state(al_node_storage_impl *impl) {
    AL_TRY(file_sync(impl->nodes_file));
    return file_sync(impl->values_file);
}

al_status al_node_storage_commit_block(al_node_storage *storage,
                                       const al_state *state,
                                       al_bytes encoded_block) {
    if (storage == NULL || storage->impl == NULL ||
        state == NULL ||
        encoded_block.data == NULL ||
        encoded_block.len < AL_BLOCK_HEADER_ENCODED_SIZE) {
        return AL_ERR_INVALID_ARG;
    }
    al_node_storage_impl *impl = (al_node_storage_impl *)storage->impl;

    al_block_header header;
    AL_TRY(al_block_header_decode(
        al_bytes_make(encoded_block.data, AL_BLOCK_HEADER_ENCODED_SIZE),
        &header));
    if (header.version != AL_BLOCK_VERSION ||
        header.chain_id != impl->chain_id ||
        header.height != (al_height)impl->block_count ||
        header.height != state->height ||
        !al_hash_eq(&header.state_root, &state->root)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }
    if (impl->has_head) {
        al_hash256 parent_hash;
        al_block_header_hash(&impl->head, &parent_hash);
        if (!al_hash_eq(&header.parent_hash, &parent_hash)) {
            return AL_ERR_CONSENSUS_VIOLATION;
        }
    } else if (!al_hash_is_zero(&header.parent_hash)) {
        return AL_ERR_CONSENSUS_VIOLATION;
    }

    al_u8 record_header[STORAGE_CHAIN_HEADER];
    memset(record_header, 0, sizeof(record_header));
    memcpy(record_header, CHAIN_MAGIC, sizeof(CHAIN_MAGIC));
    put_u16(record_header + 4u, STORAGE_FORMAT_VERSION);
    put_u64(record_header + 8u, header.height);
    al_hash256 block_hash;
    al_block_header_hash(&header, &block_hash);
    memcpy(record_header + 16u, block_hash.bytes, AL_HASH_SIZE);
    memcpy(record_header + 48u, header.state_root.bytes, AL_HASH_SIZE);
    put_u64(record_header + 80u, (al_u64)encoded_block.len);

    al_sha256_ctx checksum_context;
    al_hash256 checksum;
    al_sha256_init(&checksum_context);
    al_sha256_update(&checksum_context, record_header, sizeof(record_header));
    al_sha256_update(&checksum_context, encoded_block.data, encoded_block.len);
    al_sha256_final(&checksum_context, &checksum);

    AL_TRY(block_offsets_prepare(impl));
    AL_TRY(sync_state(impl));
    al_u64 offset = 0u;
    AL_TRY(file_size(impl->chain_file, &offset));
    al_status status = write_exact(impl->chain_file, record_header,
                                   sizeof(record_header));
    if (status == AL_OK) {
        status = write_exact(impl->chain_file, encoded_block.data,
                             encoded_block.len);
    }
    if (status == AL_OK) {
        status = write_exact(impl->chain_file, checksum.bytes, AL_HASH_SIZE);
    }
    if (status == AL_OK) {
        status = file_sync(impl->chain_file);
    }
    if (status != AL_OK) {
        (void)file_truncate(impl->chain_file, offset);
        return status;
    }

    AL_TRY(block_offsets_append(impl, offset));
    impl->head = header;
    impl->has_head = AL_TRUE;
    return AL_OK;
}

al_status al_node_storage_commit_finalized_block(
    al_node_storage *storage, const al_state *state, al_bytes encoded_block,
    al_bytes encoded_certificate) {
    if (storage == NULL || storage->impl == NULL || state == NULL ||
        encoded_block.data == NULL || encoded_block.len == 0u ||
        encoded_certificate.data == NULL || encoded_certificate.len == 0u ||
        encoded_certificate.len >
            AL_FINALITY_CERTIFICATE_MAX_ENCODED_SIZE) {
        return AL_ERR_INVALID_ARG;
    }
    al_node_storage_impl *impl = (al_node_storage_impl *)storage->impl;
    if (impl->finality_count != impl->block_count) {
        return AL_ERR_STATE_CORRUPT;
    }

    al_block_header block_header;
    AL_TRY(al_block_header_decode(
        al_bytes_slice(encoded_block, 0u, AL_BLOCK_HEADER_ENCODED_SIZE),
        &block_header));
    al_hash256 block_hash;
    al_block_header_hash(&block_header, &block_hash);

    al_finality_certificate *certificate =
        (al_finality_certificate *)malloc(sizeof(*certificate));
    if (certificate == NULL) return AL_ERR_OUT_OF_MEMORY;
    al_status status = al_finality_certificate_decode(encoded_certificate,
                                                       certificate);
    if (status == AL_OK &&
        (certificate->version != AL_CONSENSUS_VERSION ||
         certificate->chain_id != impl->chain_id ||
         certificate->height != block_header.height ||
         certificate->height != (al_height)impl->finality_count ||
         !al_hash_eq(&certificate->block_hash, &block_hash))) {
        status = AL_ERR_CONSENSUS_VIOLATION;
    }
    free(certificate);
    if (status != AL_OK) return status;

    AL_TRY(finality_offsets_prepare(impl));
    al_u8 record_header[STORAGE_FINALITY_HEADER];
    memset(record_header, 0, sizeof(record_header));
    memcpy(record_header, FINALITY_MAGIC, sizeof(FINALITY_MAGIC));
    put_u16(record_header + 4u, STORAGE_FORMAT_VERSION);
    put_u64(record_header + 8u, block_header.height);
    memcpy(record_header + 16u, block_hash.bytes, AL_HASH_SIZE);
    put_u64(record_header + 48u, (al_u64)encoded_certificate.len);

    al_sha256_ctx checksum_context;
    al_hash256 checksum;
    al_sha256_init(&checksum_context);
    al_sha256_update(&checksum_context, record_header, sizeof(record_header));
    al_sha256_update(&checksum_context, encoded_certificate.data,
                     encoded_certificate.len);
    al_sha256_final(&checksum_context, &checksum);

    al_u64 finality_offset = 0u;
    AL_TRY(file_size(impl->finality_file, &finality_offset));
    status = write_exact(impl->finality_file, record_header,
                         sizeof(record_header));
    if (status == AL_OK) {
        status = write_exact(impl->finality_file, encoded_certificate.data,
                             encoded_certificate.len);
    }
    if (status == AL_OK) {
        status = write_exact(impl->finality_file, checksum.bytes,
                             AL_HASH_SIZE);
    }
    if (status == AL_OK) status = file_sync(impl->finality_file);
    if (status != AL_OK) {
        (void)file_truncate(impl->finality_file, finality_offset);
        return status;
    }

    status = al_node_storage_commit_block(storage, state, encoded_block);
    if (status != AL_OK) {
        (void)file_truncate(impl->finality_file, finality_offset);
        return status;
    }
    impl->finality_offsets[impl->finality_count++] = finality_offset;
    return AL_OK;
}

al_status al_node_storage_read_block(al_node_storage *storage,
                                     al_height height, al_bytes_mut out,
                                     al_size *written) {
    if (written == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    *written = 0u;
    if (storage == NULL || storage->impl == NULL ||
        (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_node_storage_impl *impl = (al_node_storage_impl *)storage->impl;
    if (height >= (al_height)impl->block_count) {
        return AL_ERR_NOT_FOUND;
    }

    al_u8 header[STORAGE_CHAIN_HEADER];
    al_u64 payload_size = 0u;
    al_u64 offset = impl->block_offsets[(al_size)height];
    AL_TRY(chain_record_header(impl->chain_file, offset, header,
                               &payload_size));
    if (payload_size > (al_u64)SIZE_MAX) {
        return AL_ERR_OUT_OF_RANGE;
    }
    *written = (al_size)payload_size;
    if (out.len < *written || (out.data == NULL && *written != 0u)) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    AL_TRY(file_seek(impl->chain_file, offset + STORAGE_CHAIN_HEADER));
    return read_exact(impl->chain_file, out.data, *written);
}

al_status al_node_storage_read_finality(al_node_storage *storage,
                                        al_height height, al_bytes_mut out,
                                        al_size *written) {
    if (written == NULL) return AL_ERR_INVALID_ARG;
    *written = 0u;
    if (storage == NULL || storage->impl == NULL ||
        (out.data == NULL && out.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_node_storage_impl *impl = (al_node_storage_impl *)storage->impl;
    if (height >= (al_height)impl->finality_count) return AL_ERR_NOT_FOUND;

    al_u8 header[STORAGE_FINALITY_HEADER];
    al_u64 payload_size = 0u;
    al_u64 offset = impl->finality_offsets[(al_size)height];
    AL_TRY(finality_record_header(impl->finality_file, offset, header,
                                  &payload_size));
    if (payload_size > (al_u64)SIZE_MAX) return AL_ERR_OUT_OF_RANGE;
    *written = (al_size)payload_size;
    if (out.len < *written || (out.data == NULL && *written != 0u)) {
        return AL_ERR_BUFFER_TOO_SMALL;
    }
    AL_TRY(file_seek(impl->finality_file,
                     offset + STORAGE_FINALITY_HEADER));
    return read_exact(impl->finality_file, out.data, *written);
}

al_status al_node_storage_prepare_genesis(al_node_storage *storage,
                                          const al_genesis *genesis,
                                          al_arena *arena) {
    if (storage == NULL || storage->impl == NULL || genesis == NULL ||
        arena == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    /* Once the chain has a block, the live state already descends from the
     * genesis tree and nothing needs rebuilding. */
    if (al_node_storage_block_count(storage) != 0u) {
        return AL_OK;
    }

    al_state rebuilt;
    al_state_store store = al_node_storage_state_store(storage);
    al_status status =
        al_state_init(&rebuilt, &store, arena,
                      genesis->fees.storage_deposit_per_byte);
    for (al_size i = 0u; status == AL_OK && i < genesis->allocation_count;
         ++i) {
        al_account account;
        memset(&account, 0, sizeof(account));
        account.address = genesis->allocations[i].address;
        account.balance = genesis->allocations[i].balance;
        status = al_state_upsert(&rebuilt, &account);
    }
    if (status != AL_OK) return status;

    /* The allocation list is the only replayable description of the initial
     * tree; anything else bound into the file is a corrupt genesis. */
    if (!al_hash_eq(&rebuilt.root, &genesis->initial_state_root)) {
        return AL_ERR_STATE_CORRUPT;
    }
    return AL_OK;
}

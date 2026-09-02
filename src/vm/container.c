/*
 * ALVM container format: encode, decode, load and validate.
 *
 * The container is the on-chain/wire representation of a program. This file
 * handles the binary format; the execution loop lives in vm.c.
 */

#include "astrolune/vm.h"
#include "internal.h"
#include "internal/common.h"

static const al_u8 al_vm_magic[4] = { 'A', 'L', 'V', 'M' };

/* --------------------------------------------------------------------------
 * Encoding
 * -------------------------------------------------------------------------- */

static void vm_function_write(al_writer *writer,
                              const al_vm_function *function) {
    al_writer_u32(writer, function->offset);
    al_writer_u16(writer, function->parameter_count);
    al_writer_u16(writer, function->result_count);
    al_writer_u16(writer, function->max_stack);
    al_writer_u16(writer, function->reserved);
}

al_status al_vm_container_encode(const al_vm_function *functions,
                                 al_size function_count, al_bytes code,
                                 al_bytes_mut out, al_size *written) {
    if (written == NULL || functions == NULL || function_count == 0u ||
        function_count > AL_VM_MAX_FUNCTIONS || code.len == 0u ||
        code.len > AL_VM_MAX_CODE_SIZE || code.data == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    *written = 0u;
    al_writer writer;
    al_writer_init(&writer, out.data, out.len);
    al_writer_raw(&writer, al_vm_magic, sizeof(al_vm_magic));
    al_writer_u16(&writer, AL_VM_CONTAINER_VERSION);
    al_writer_u16(&writer, AL_VM_ISA_VERSION);
    al_writer_u32(&writer, 0u);
    al_writer_varint(&writer, function_count);
    for (al_size i = 0u; i < function_count; ++i) {
        vm_function_write(&writer, &functions[i]);
    }
    al_writer_varint(&writer, code.len);
    al_writer_raw(&writer, code.data, code.len);
    *written = al_writer_len(&writer);
    return al_writer_finish(&writer);
}

/* --------------------------------------------------------------------------
 * Decoding
 * -------------------------------------------------------------------------- */

al_status al_vm_program_decode(al_bytes container, al_arena *arena,
                               al_vm_program *out) {
    if (out == NULL || arena == NULL || container.data == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_reader reader;
    al_reader_init(&reader, container);
    al_bytes magic = al_reader_take(&reader, sizeof(al_vm_magic));
    if (!al_bytes_eq(magic, al_bytes_make(al_vm_magic, sizeof(al_vm_magic)))) {
        al_reader_fail(&reader, AL_ERR_MALFORMED);
    }

    al_memzero(out, sizeof(*out));
    out->container = container;
    out->container_version = al_reader_u16(&reader);
    out->isa_version = al_reader_u16(&reader);
    out->flags = al_reader_u32(&reader);
    if (out->container_version != AL_VM_CONTAINER_VERSION ||
        out->isa_version != AL_VM_ISA_VERSION || out->flags != 0u) {
        al_reader_fail(&reader, AL_ERR_UNSUPPORTED);
    }

    al_u64 count = al_reader_varint(&reader);
    if (count == 0u || count > AL_VM_MAX_FUNCTIONS) {
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
        count = 0u;
    }
    al_vm_function *functions = AL_ARENA_NEW_ARRAY(arena, al_vm_function,
                                                    (al_size)count);
    if (functions == NULL && count != 0u) {
        return AL_ERR_OUT_OF_MEMORY;
    }
    for (al_size i = 0u; i < (al_size)count; ++i) {
        functions[i].offset = al_reader_u32(&reader);
        functions[i].parameter_count = al_reader_u16(&reader);
        functions[i].result_count = al_reader_u16(&reader);
        functions[i].max_stack = al_reader_u16(&reader);
        functions[i].reserved = al_reader_u16(&reader);
    }

    al_u64 code_len = al_reader_varint(&reader);
    if (code_len == 0u || code_len > AL_VM_MAX_CODE_SIZE ||
        code_len > (al_u64)SIZE_MAX) {
        al_reader_fail(&reader, AL_ERR_OUT_OF_RANGE);
        code_len = 0u;
    }
    out->code = al_reader_take(&reader, (al_size)code_len);
    AL_TRY(al_reader_finish(&reader));
    out->functions = functions;
    out->function_count = (al_size)count;
    return AL_OK;
}

/* --------------------------------------------------------------------------
 * Loading and validation
 * -------------------------------------------------------------------------- */

al_status al_vm_program_load(al_bytes container, const al_vm_config *config,
                             al_arena *arena, al_vm_program *out) {
    if (arena == NULL || out == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_vm_config defaults = al_vm_config_default();
    if (config == NULL) {
        config = &defaults;
    }
    al_arena_mark mark = al_arena_save(arena);
    al_status status = al_vm_program_decode(container, arena, out);
    if (status == AL_OK) {
        al_arena_mark validation_mark = al_arena_save(arena);
        status = al_vm_validate_program(out, config, arena);
        al_arena_restore(arena, validation_mark);
    }
    if (status != AL_OK) {
        al_arena_restore(arena, mark);
        al_memzero(out, sizeof(*out));
    }
    return status;
}

al_status al_vm_validate(al_bytes container, const al_vm_config *config,
                         al_arena *scratch) {
    if (scratch == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    al_arena_mark mark = al_arena_save(scratch);
    al_vm_program program;
    al_status status = al_vm_program_load(container, config, scratch, &program);
    al_arena_restore(scratch, mark);
    return status;
}

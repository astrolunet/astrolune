#include "altest.h"
#include "astrolune/vm.h"

typedef struct code_builder {
    al_u8 data[512];
    al_size len;
} code_builder;

static void emit_u8(code_builder *builder, al_u8 value) {
    builder->data[builder->len++] = value;
}

static void emit_u16(code_builder *builder, al_u16 value) {
    builder->data[builder->len++] = (al_u8)(value & 0xffu);
    builder->data[builder->len++] = (al_u8)(value >> 8u);
}

static void emit_u32(code_builder *builder, al_u32 value) {
    for (al_u32 i = 0u; i < 4u; ++i) {
        builder->data[builder->len++] = (al_u8)(value >> (i * 8u));
    }
}

static void emit_push(code_builder *builder, al_u64 value) {
    emit_u8(builder, AL_VM_PUSH64);
    for (al_u32 i = 0u; i < 8u; ++i) {
        builder->data[builder->len++] = (al_u8)(value >> (i * 8u));
    }
}

static void emit_jump(code_builder *builder, al_vm_opcode opcode,
                      al_u32 target) {
    emit_u8(builder, (al_u8)opcode);
    emit_u32(builder, target);
}

static void emit_indexed(code_builder *builder, al_vm_opcode opcode,
                         al_u16 index) {
    emit_u8(builder, (al_u8)opcode);
    emit_u16(builder, index);
}

static al_size make_container(const code_builder *builder,
                              const al_vm_function *functions,
                              al_size function_count, al_u8 *out,
                              al_size out_capacity) {
    al_size written = 0u;
    al_bytes_mut output = { out, out_capacity };
    AL_CHECK_EQ_STATUS(al_vm_container_encode(
                           functions, function_count,
                           al_bytes_make(builder->data, builder->len),
                           output, &written), AL_OK);
    return written;
}

static al_size make_single_container(const code_builder *builder, al_u8 *out,
                                     al_size out_capacity) {
    const al_vm_function function = {
        0u, 0u, 0u, AL_VM_DEFAULT_STACK, 0u
    };
    return make_container(builder, &function, 1u, out, out_capacity);
}

static al_status execute_builder(const code_builder *builder,
                                 al_bytes calldata,
                                 const al_vm_config *config,
                                 const al_vm_execution_context *execution,
                                 const al_vm_host *host,
                                 al_vm_result *result,
                                 al_arena *arena) {
    al_u8 container[1024];
    al_size length = make_single_container(builder, container,
                                           sizeof(container));
    return al_vm_execute(al_bytes_make(container, length), calldata, config,
                         execution, host, arena, result);
}

AL_TEST(container_and_validation) {
    code_builder builder = { { 0u }, 0u };
    emit_u8(&builder, AL_VM_STOP);
    al_u8 container[128];
    al_size length = make_single_container(&builder, container,
                                           sizeof(container));
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    AL_CHECK_EQ_STATUS(al_vm_validate(al_bytes_make(container, length), NULL,
                                     &arena), AL_OK);

    al_vm_program program;
    AL_CHECK_EQ_STATUS(al_vm_program_load(al_bytes_make(container, length),
                                         NULL, &arena, &program), AL_OK);
    AL_CHECK_EQ_U64(program.container_version, AL_VM_CONTAINER_VERSION);
    AL_CHECK_EQ_U64(program.isa_version, AL_VM_ISA_VERSION);
    AL_CHECK_EQ_U64(program.function_count, 1u);
    AL_CHECK_EQ_U64(program.code.len, 1u);

    container[0] ^= 1u;
    AL_CHECK_EQ_STATUS(al_vm_validate(al_bytes_make(container, length), NULL,
                                     &arena), AL_ERR_MALFORMED);
    container[0] ^= 1u;
    container[length] = 0u;
    AL_CHECK_EQ_STATUS(al_vm_validate(al_bytes_make(container, length + 1u),
                                     NULL, &arena), AL_ERR_TRAILING_BYTES);
    al_arena_destroy(&arena);
}

AL_TEST(validator_rejects_bad_control_flow) {
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_u8 container[256];

    code_builder fallthrough = { { 0u }, 0u };
    emit_push(&fallthrough, 1u);
    al_size length = make_single_container(&fallthrough, container,
                                           sizeof(container));
    AL_CHECK_EQ_STATUS(al_vm_validate(al_bytes_make(container, length), NULL,
                                     &arena), AL_ERR_MALFORMED);

    code_builder bad_jump = { { 0u }, 0u };
    emit_jump(&bad_jump, AL_VM_JUMP, 1u);
    emit_u8(&bad_jump, AL_VM_STOP);
    length = make_single_container(&bad_jump, container, sizeof(container));
    AL_CHECK_EQ_STATUS(al_vm_validate(al_bytes_make(container, length), NULL,
                                     &arena), AL_ERR_MALFORMED);

    code_builder underflow = { { 0u }, 0u };
    emit_u8(&underflow, AL_VM_ADD);
    emit_u8(&underflow, AL_VM_STOP);
    length = make_single_container(&underflow, container, sizeof(container));
    AL_CHECK_EQ_STATUS(al_vm_validate(al_bytes_make(container, length), NULL,
                                     &arena), AL_ERR_MALFORMED);
    al_arena_destroy(&arena);
}

AL_TEST(arithmetic_memory_and_return) {
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 7u);
    emit_push(&builder, 5u);
    emit_u8(&builder, AL_VM_ADD);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_LOAD64);
    emit_push(&builder, 8u);
    emit_u8(&builder, AL_VM_MOD);
    emit_push(&builder, 8u);
    emit_u8(&builder, AL_VM_STORE8);
    emit_push(&builder, 8u);
    emit_push(&builder, 1u);
    emit_u8(&builder, AL_VM_RETURN);

    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 1u);
    if (result.return_data.len == 1u) {
        AL_CHECK_EQ_U64(result.return_data.data[0], 4u);
    }
    AL_CHECK(result.resources.compute != 0u);
    AL_CHECK_EQ_U64(result.resources.memory, 1u);
    al_arena_destroy(&arena);
}

AL_TEST(calldata_and_resource_limits) {
    static const al_u8 input[] = { 0xaau, 0xbbu, 0xccu };
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 0u);
    emit_push(&builder, 4u);
    emit_push(&builder, sizeof(input));
    emit_u8(&builder, AL_VM_CALLDATA_COPY);
    emit_push(&builder, 4u);
    emit_push(&builder, sizeof(input));
    emit_u8(&builder, AL_VM_RETURN);

    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(
                           &builder, al_bytes_make(input, sizeof(input)), NULL,
                           NULL, NULL, &result, &arena), AL_OK);
    AL_CHECK(al_bytes_eq(result.return_data,
                         al_bytes_make(input, sizeof(input))));

    al_vm_config config = al_vm_config_default();
    config.resource_limit.compute = 1u;
    AL_CHECK_EQ_STATUS(execute_builder(
                           &builder, al_bytes_make(input, sizeof(input)),
                           &config, NULL, NULL, &result, &arena),
                       AL_ERR_RESOURCE_LIMIT);
    al_arena_destroy(&arena);
}

AL_TEST(internal_calls) {
    code_builder builder = { { 0u }, 0u };
    emit_indexed(&builder, AL_VM_CALL, 1u);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_STORE8);
    emit_push(&builder, 0u);
    emit_push(&builder, 1u);
    emit_u8(&builder, AL_VM_RETURN);
    al_u32 second_offset = (al_u32)builder.len;
    emit_push(&builder, 42u);
    emit_u8(&builder, AL_VM_RET);
    const al_vm_function functions[] = {
        { 0u, 0u, 0u, 2u, 0u },
        { second_offset, 0u, 1u, 1u, 0u }
    };
    al_u8 container[512];
    al_size length = make_container(&builder, functions, AL_COUNTOF(functions),
                                    container, sizeof(container));
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(al_vm_execute(al_bytes_make(container, length),
                                     al_bytes_empty(), NULL, NULL, NULL,
                                     &arena, &result), AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 1u);
    if (result.return_data.len == 1u) {
        AL_CHECK_EQ_U64(result.return_data.data[0], 42u);
    }
    al_vm_execution_context entry;
    memset(&entry, 0, sizeof(entry));
    entry.entrypoint = 1u;
    AL_CHECK_EQ_STATUS(al_vm_execute(al_bytes_make(container, length),
                                     al_bytes_empty(), NULL, &entry, NULL,
                                     &arena, &result), AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 0u);
    al_arena_destroy(&arena);
}

static al_status test_host(void *context, al_vm_host_id id,
                           al_vm_host_io *io) {
    AL_UNUSED(context);
    if (id != AL_VM_HOST_BLOCK_HEIGHT || io->result_capacity != 1u) {
        return AL_ERR_UNSUPPORTED;
    }
    io->results[0] = io->execution->block_height;
    io->result_count = 1u;
    return AL_OK;
}

AL_TEST(host_calls_and_reentrancy) {
    code_builder builder = { { 0u }, 0u };
    emit_indexed(&builder, AL_VM_HOST, AL_VM_HOST_BLOCK_HEIGHT);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_STORE8);
    emit_push(&builder, 0u);
    emit_push(&builder, 1u);
    emit_u8(&builder, AL_VM_RETURN);
    al_vm_execution_context execution;
    memset(&execution, 0, sizeof(execution));
    execution.block_height = 77u;
    execution.current_contract.bytes[0] = 1u;
    const al_vm_host host = { NULL, test_host };
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL,
                                       &execution, &host, &result, &arena),
                       AL_OK);
    AL_CHECK_EQ_U64(result.return_data.data[0], 77u);

    al_address active = execution.current_contract;
    execution.active_contracts = &active;
    execution.active_contract_count = 1u;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL,
                                       &execution, &host, &result, &arena),
                       AL_ERR_REENTRANCY);
    al_arena_destroy(&arena);
}

AL_TEST(revert_and_runtime_traps) {
    code_builder revert = { { 0u }, 0u };
    emit_push(&revert, 9u);
    emit_push(&revert, 0u);
    emit_u8(&revert, AL_VM_STORE8);
    emit_push(&revert, 0u);
    emit_push(&revert, 1u);
    emit_u8(&revert, AL_VM_REVERT);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&revert, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena),
                       AL_ERR_REVERTED);
    AL_CHECK_EQ_U64(result.return_data.len, 1u);

    code_builder divide = { { 0u }, 0u };
    emit_push(&divide, 1u);
    emit_push(&divide, 0u);
    emit_u8(&divide, AL_VM_DIV);
    emit_u8(&divide, AL_VM_STOP);
    AL_CHECK_EQ_STATUS(execute_builder(&divide, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena),
                       AL_ERR_DIVIDE_BY_ZERO);
    al_arena_destroy(&arena);
}

AL_TEST(iszero_opcode) {
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_ISZERO);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_push(&builder, 0u);
    emit_push(&builder, 8u);
    emit_u8(&builder, AL_VM_RETURN);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 8u);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 1u);
    }

    code_builder builder2 = { { 0u }, 0u };
    emit_push(&builder2, 42u);
    emit_u8(&builder2, AL_VM_ISZERO);
    emit_push(&builder2, 0u);
    emit_u8(&builder2, AL_VM_STORE64);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 8u);
    emit_u8(&builder2, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder2, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0u);
    }
    al_arena_destroy(&arena);
}

AL_TEST(byte_opcode) {
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 0u);
    emit_push(&builder, 0x0102030405060708ull);
    emit_u8(&builder, AL_VM_BYTE);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_push(&builder, 0u);
    emit_push(&builder, 8u);
    emit_u8(&builder, AL_VM_RETURN);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0x01u);
    }

    code_builder builder2 = { { 0u }, 0u };
    emit_push(&builder2, 7u);
    emit_push(&builder2, 0x0102030405060708ull);
    emit_u8(&builder2, AL_VM_BYTE);
    emit_push(&builder2, 0u);
    emit_u8(&builder2, AL_VM_STORE64);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 8u);
    emit_u8(&builder2, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder2, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0x08u);
    }

    code_builder builder3 = { { 0u }, 0u };
    emit_push(&builder3, 8u);
    emit_push(&builder3, 0x0102030405060708ull);
    emit_u8(&builder3, AL_VM_BYTE);
    emit_push(&builder3, 0u);
    emit_u8(&builder3, AL_VM_STORE64);
    emit_push(&builder3, 0u);
    emit_push(&builder3, 8u);
    emit_u8(&builder3, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder3, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0u);
    }
    al_arena_destroy(&arena);
}

AL_TEST(signextend_opcode) {
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 0u);
    emit_push(&builder, 0xffu);
    emit_u8(&builder, AL_VM_SIGNEXTEND);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_push(&builder, 0u);
    emit_push(&builder, 8u);
    emit_u8(&builder, AL_VM_RETURN);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0xffffffffffffffffull);
    }

    code_builder builder2 = { { 0u }, 0u };
    emit_push(&builder2, 0u);
    emit_push(&builder2, 0x7fu);
    emit_u8(&builder2, AL_VM_SIGNEXTEND);
    emit_push(&builder2, 0u);
    emit_u8(&builder2, AL_VM_STORE64);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 8u);
    emit_u8(&builder2, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder2, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0x7fu);
    }

    code_builder builder3 = { { 0u }, 0u };
    emit_push(&builder3, 1u);
    emit_push(&builder3, 0x7fu);
    emit_u8(&builder3, AL_VM_SIGNEXTEND);
    emit_push(&builder3, 0u);
    emit_u8(&builder3, AL_VM_STORE64);
    emit_push(&builder3, 0u);
    emit_push(&builder3, 8u);
    emit_u8(&builder3, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder3, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    if (result.return_data.len == 8u) {
        al_u64 val = 0u;
        for (al_size i = 0u; i < 8u; ++i)
            val |= (al_u64)result.return_data.data[i] << (i * 8u);
        AL_CHECK_EQ_U64(val, 0x7fu);
    }
    al_arena_destroy(&arena);
}

AL_TEST(sha3_opcode) {
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 0u);
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_SHA3);
    emit_push(&builder, 100u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_push(&builder, 0u);
    emit_push(&builder, 8u);
    emit_u8(&builder, AL_VM_RETURN);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 8u);
    AL_CHECK(result.resources.compute > 0u);

    code_builder builder2 = { { 0u }, 0u };
    emit_push(&builder2, 42u);
    emit_push(&builder2, 0u);
    emit_u8(&builder2, AL_VM_STORE64);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 8u);
    emit_u8(&builder2, AL_VM_SHA3);
    emit_push(&builder2, 100u);
    emit_u8(&builder2, AL_VM_STORE64);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 8u);
    emit_u8(&builder2, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder2, al_bytes_empty(), NULL, NULL,
                                       NULL, &result, &arena), AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 8u);
    al_arena_destroy(&arena);
}

AL_TEST(callsvalue_codesize_codecopy) {
    code_builder builder = { { 0u }, 0u };
    emit_u8(&builder, AL_VM_CALLVALUE);
    emit_push(&builder, 100u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_u8(&builder, AL_VM_CODESIZE);
    emit_push(&builder, 108u);
    emit_u8(&builder, AL_VM_STORE64);
    emit_push(&builder, 0u);
    emit_push(&builder, 100u);
    emit_push(&builder, 16u);
    emit_u8(&builder, AL_VM_RETURN);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    al_vm_execution_context execution;
    memset(&execution, 0, sizeof(execution));
    execution.value = 12345u;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL,
                                       &execution, NULL, &result, &arena),
                       AL_OK);
    if (result.return_data.len == 16u) {
        al_u64 cv = 0u, cs = 0u;
        for (al_size i = 0u; i < 8u; ++i) {
            cv |= (al_u64)result.return_data.data[i] << (i * 8u);
            cs |= (al_u64)result.return_data.data[i + 8u] << (i * 8u);
        }
        AL_CHECK_EQ_U64(cv, 12345u);
        AL_CHECK_EQ_U64(cs, 0u);
    }
    code_builder builder2 = { { 0u }, 0u };
    emit_push(&builder2, 42u);
    emit_push(&builder2, 100u);
    emit_u8(&builder2, AL_VM_STORE8);
    emit_push(&builder2, 100u);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 0u);
    emit_u8(&builder2, AL_VM_CODECOPY);
    emit_push(&builder2, 100u);
    emit_push(&builder2, 1u);
    emit_u8(&builder2, AL_VM_RETURN);
    AL_CHECK_EQ_STATUS(execute_builder(&builder2, al_bytes_empty(), NULL,
                                       NULL, NULL, &result, &arena),
                       AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 1u);
    if (result.return_data.len == 1u)
        AL_CHECK_EQ_U64(result.return_data.data[0], 42u);
    al_arena_destroy(&arena);
}

AL_TEST(address_and_caller) {
    code_builder builder = { { 0u }, 0u };
    emit_push(&builder, 0u);
    emit_u8(&builder, AL_VM_ADDRESS);
    emit_push(&builder, 0u);
    emit_push(&builder, 32u);
    emit_u8(&builder, AL_VM_RETURN);
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 0u), AL_OK);
    al_vm_result result;
    al_vm_execution_context execution;
    memset(&execution, 0, sizeof(execution));
    execution.current_contract.bytes[0] = 0xabu;
    AL_CHECK_EQ_STATUS(execute_builder(&builder, al_bytes_empty(), NULL,
                                       &execution, NULL, &result, &arena),
                       AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 32u);
    if (result.return_data.len == 32u) {
        AL_CHECK_EQ_U64(result.return_data.data[0], 0xabu);
    }

    code_builder builder2 = { { 0u }, 0u };
    emit_push(&builder2, 0u);
    emit_u8(&builder2, AL_VM_CALLER);
    emit_push(&builder2, 0u);
    emit_push(&builder2, 32u);
    emit_u8(&builder2, AL_VM_RETURN);
    execution.sender.bytes[0] = 0xcdu;
    AL_CHECK_EQ_STATUS(execute_builder(&builder2, al_bytes_empty(), NULL,
                                       &execution, NULL, &result, &arena),
                       AL_OK);
    AL_CHECK_EQ_U64(result.return_data.len, 32u);
    if (result.return_data.len == 32u) {
        AL_CHECK_EQ_U64(result.return_data.data[0], 0xcdu);
    }
    al_arena_destroy(&arena);
}

AL_TEST(cost_table_is_total) {
    for (al_u32 opcode = AL_VM_STOP; opcode <= AL_VM_HOST; ++opcode) {
        AL_CHECK(al_vm_compute_cost((al_vm_opcode)opcode) != UINT64_MAX);
    }
    /* ISA v2 opcodes */
    AL_CHECK(al_vm_compute_cost(AL_VM_ISZERO) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_BYTE) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_SIGNEXTEND) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_SHA3) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_MLOAD) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_MSTORE) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_SLOAD) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_SSTORE) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_ADDRESS) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_CALLER) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_CALLVALUE) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_CODESIZE) != UINT64_MAX);
    AL_CHECK(al_vm_compute_cost(AL_VM_CODECOPY) != UINT64_MAX);
    for (al_u32 host = AL_VM_HOST_SENDER;
         host <= AL_VM_HOST_CALL_CONTRACT; ++host) {
        AL_CHECK(al_vm_host_compute_cost((al_vm_host_id)host) != UINT64_MAX);
    }
}

#define AL_TEST_SUITE_NAME "test_vm"
AL_TEST_MAIN {
    AL_RUN(container_and_validation);
    AL_RUN(validator_rejects_bad_control_flow);
    AL_RUN(arithmetic_memory_and_return);
    AL_RUN(calldata_and_resource_limits);
    AL_RUN(internal_calls);
    AL_RUN(host_calls_and_reentrancy);
    AL_RUN(revert_and_runtime_traps);
    AL_RUN(cost_table_is_total);
    AL_RUN(iszero_opcode);
    AL_RUN(byte_opcode);
    AL_RUN(signextend_opcode);
    AL_RUN(sha3_opcode);
    AL_RUN(callsvalue_codesize_codecopy);
    AL_RUN(address_and_caller);
}

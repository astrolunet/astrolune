/*
 * ALVM execution loop.
 *
 * The container format, instruction decoding and static validation live in
 * container.c and decode.c respectively. This file owns the runtime:
 * the stack machine, memory model and host-function dispatch.
 */

#include "astrolune/vm.h"
#include "internal.h"
#include "internal/common.h"

#include "astrolune/hash.h"
#include "astrolune/state.h"

#include <string.h>

/* --------------------------------------------------------------------------
 * Cost tables and defaults
 * -------------------------------------------------------------------------- */

al_vm_config al_vm_config_default(void) {
    al_vm_config config;
    config.stack_limit = AL_VM_DEFAULT_STACK;
    config.memory_limit = AL_VM_DEFAULT_MEMORY;
    config.call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
    config.resource_limit.compute = UINT64_MAX;
    config.resource_limit.memory = UINT64_MAX;
    config.resource_limit.storage = UINT64_MAX;
    config.resource_limit.bandwidth = UINT64_MAX;
    config.schedule = NULL;
    return config;
}

al_vm_resource_schedule al_vm_resource_schedule_default(void) {
    al_vm_resource_schedule schedule;
    for (al_size i = 0u; i < AL_VM_OPCODE_COUNT; ++i)
        schedule.opcode[i] = al_vm_compute_cost((al_vm_opcode)i);
    for (al_size i = 0u; i < AL_VM_HOST_COUNT; ++i)
        schedule.host[i] = al_vm_host_compute_cost((al_vm_host_id)i);
    return schedule;
}

al_u64 al_vm_compute_cost(al_vm_opcode opcode) {
    switch (opcode) {
    case AL_VM_STOP:
    case AL_VM_RETURN:
    case AL_VM_REVERT:
    case AL_VM_RET:
        return 1u;
    case AL_VM_PUSH64:
    case AL_VM_DUP:
    case AL_VM_DROP:
    case AL_VM_SWAP:
    case AL_VM_CALLDATA_SIZE:
        return 1u;
    case AL_VM_JUMP:
    case AL_VM_JUMPI:
    case AL_VM_CALL:
        return 2u;
    case AL_VM_ADD:
    case AL_VM_SUB:
    case AL_VM_MUL:
    case AL_VM_DIV:
    case AL_VM_MOD:
    case AL_VM_EQ:
    case AL_VM_LT:
    case AL_VM_GT:
    case AL_VM_LE:
    case AL_VM_GE:
    case AL_VM_AND:
    case AL_VM_OR:
    case AL_VM_XOR:
    case AL_VM_NOT:
    case AL_VM_SHL:
    case AL_VM_SHR:
        return 3u;
    case AL_VM_LOAD8:
    case AL_VM_STORE8:
    case AL_VM_LOAD64:
    case AL_VM_STORE64:
    case AL_VM_CALLDATA_COPY:
        return 5u;
    case AL_VM_HOST:
        return 2u;
    /* ISA v2 extension costs */
    case AL_VM_ISZERO:
        return 1u;
    case AL_VM_BYTE:
    case AL_VM_SIGNEXTEND:
        return 3u;
    case AL_VM_SHA3:
        return 30u;
    case AL_VM_SLOAD:
        return 50u;
    case AL_VM_SSTORE:
        return 200u;
    case AL_VM_ADDRESS:
    case AL_VM_CALLER:
        return 2u;
    case AL_VM_CALLVALUE:
    case AL_VM_CODESIZE:
        return 2u;
    case AL_VM_CODECOPY:
        return 5u;
    case AL_VM_MLOAD:
    case AL_VM_MSTORE:
        return 5u;
    case AL_VM_OPCODE_SENTINEL:
        break;
    }
    return UINT64_MAX;
}

al_u64 al_vm_host_compute_cost(al_vm_host_id id) {
    switch (id) {
    case AL_VM_HOST_SENDER:
    case AL_VM_HOST_CURRENT_ADDRESS:
    case AL_VM_HOST_BLOCK_HEIGHT:
    case AL_VM_HOST_PROTOCOL_DAY:
    case AL_VM_HOST_BALANCE:
        return 5u;
    case AL_VM_HOST_TRANSFER:
        return 40u;
    case AL_VM_HOST_STORAGE_GET:
        return 50u;
    case AL_VM_HOST_STORAGE_SET:
    case AL_VM_HOST_STORAGE_DELETE:
        return 200u;
    case AL_VM_HOST_EMIT_EVENT:
        return 25u;
    case AL_VM_HOST_HASH_TAGGED:
        return 60u;
    case AL_VM_HOST_VERIFY_SIGNATURE:
        return 500u;
    case AL_VM_HOST_CALL_CONTRACT:
        return 100u;
    case AL_VM_HOST_ID_SENTINEL:
        break;
    }
    return UINT64_MAX;
}

static al_u64 vm_opcode_cost(const al_vm_config *config, al_vm_opcode opcode) {
    return (config->schedule != NULL)
               ? config->schedule->opcode[(al_size)opcode]
               : al_vm_compute_cost(opcode);
}

static al_u64 vm_host_cost(const al_vm_config *config, al_vm_host_id id) {
    return (config->schedule != NULL)
               ? config->schedule->host[(al_size)id]
               : al_vm_host_compute_cost(id);
}

/* --------------------------------------------------------------------------
 * Execution helpers
 * -------------------------------------------------------------------------- */

static al_bool vm_address_equal(const al_address *lhs,
                                const al_address *rhs) {
    al_u8 difference = 0u;
    for (al_size i = 0u; i < AL_ADDRESS_SIZE; ++i) {
        difference |= (al_u8)(lhs->bytes[i] ^ rhs->bytes[i]);
    }
    return (difference == 0u) ? AL_TRUE : AL_FALSE;
}

typedef struct vm_frame {
    al_size return_pc;
    al_size function_index;
    al_size stack_base;
} vm_frame;

static al_status vm_push(al_u64 *stack, al_size *size, al_size limit,
                         al_u64 value) {
    if (*size == limit) {
        return AL_ERR_STACK_OVERFLOW;
    }
    stack[(*size)++] = value;
    return AL_OK;
}

static al_status vm_pop(al_u64 *stack, al_size *size, al_u64 *out) {
    if (*size == 0u) {
        return AL_ERR_VM_TRAP;
    }
    *out = stack[--(*size)];
    return AL_OK;
}

static al_status vm_charge(al_resources *used, al_u64 amount,
                           const al_vm_config *config) {
    if (UINT64_MAX - used->compute < amount) {
        return AL_ERR_ARITH_OVERFLOW;
    }
    used->compute += amount;
    return al_resources_within(*used, config->resource_limit)
               ? AL_OK : AL_ERR_RESOURCE_LIMIT;
}

static void vm_touch_memory(al_resources *used, al_u64 offset, al_u64 length) {
    if (length == 0u) return;
    al_u64 pages = (offset + length + AL_VM_MEMORY_PAGE_SIZE - 1u) /
                   AL_VM_MEMORY_PAGE_SIZE;
    if (pages > used->memory) used->memory = pages;
}

static al_status vm_finish(al_vm_result *out, al_status status) {
    out->status = status;
    return status;
}

static al_status vm_return_data(al_vm_result *out, al_arena *arena,
                                const al_u8 *memory, al_size memory_size,
                                al_u64 offset, al_u64 length,
                                al_status status) {
    if (offset > memory_size || length > memory_size - (al_size)offset) {
        return vm_finish(out, AL_ERR_MEMORY_FAULT);
    }
    al_u8 *copy = (al_u8 *)al_arena_dup(arena, memory + (al_size)offset,
                                        (al_size)length);
    if (copy == NULL && length != 0u) {
        return vm_finish(out, AL_ERR_OUT_OF_MEMORY);
    }
    out->return_data = al_bytes_make(copy, (al_size)length);
    return vm_finish(out, status);
}

/* --------------------------------------------------------------------------
 * Execution loop
 * -------------------------------------------------------------------------- */

al_status al_vm_execute(al_bytes container, al_bytes calldata,
                        const al_vm_config *config,
                        const al_vm_execution_context *execution,
                        const al_vm_host *host, al_arena *arena,
                        al_vm_result *out) {
    if (arena == NULL || out == NULL ||
        (calldata.data == NULL && calldata.len != 0u)) {
        return AL_ERR_INVALID_ARG;
    }
    al_vm_config defaults = al_vm_config_default();
    if (config == NULL) {
        config = &defaults;
    }
    al_memzero(out, sizeof(*out));
    out->status = AL_OK;

    al_vm_program program;
    al_status status = al_vm_program_load(container, config, arena, &program);
    if (status != AL_OK) {
        return vm_finish(out, status);
    }

    al_u64 *stack = AL_ARENA_NEW_ARRAY(arena, al_u64, config->stack_limit);
    al_u8 *memory = (al_u8 *)al_arena_calloc(arena, config->memory_limit, 1u);
    vm_frame *frames = AL_ARENA_NEW_ARRAY(arena, vm_frame,
                                          config->call_depth_limit);
    if (stack == NULL || memory == NULL || frames == NULL) {
        return vm_finish(out, AL_ERR_OUT_OF_MEMORY);
    }

    al_vm_execution_context local_execution;
    al_memzero(&local_execution, sizeof(local_execution));
    if (execution != NULL) {
        local_execution = *execution;
        if (execution->active_contract_count >= config->call_depth_limit ||
            (execution->active_contracts == NULL &&
             execution->active_contract_count != 0u)) {
            return vm_finish(out, AL_ERR_CALL_DEPTH);
        }
        for (al_size i = 0u; i < execution->active_contract_count; ++i) {
            if (vm_address_equal(&execution->active_contracts[i],
                                 &execution->current_contract)) {
                return vm_finish(out, AL_ERR_REENTRANCY);
            }
        }
        al_address *active = AL_ARENA_NEW_ARRAY(
            arena, al_address, execution->active_contract_count + 1u);
        if (active == NULL) {
            return vm_finish(out, AL_ERR_OUT_OF_MEMORY);
        }
        if (execution->active_contract_count != 0u) {
            al_memcpy(active, execution->active_contracts,
                      execution->active_contract_count * sizeof(*active));
        }
        active[execution->active_contract_count] = execution->current_contract;
        local_execution.active_contracts = active;
        local_execution.active_contract_count =
            execution->active_contract_count + 1u;
    }

    al_size stack_size = 0u;
    al_size frame_count = 0u;
    al_size current_function = local_execution.entrypoint;
    if (current_function >= program.function_count ||
        program.functions[current_function].parameter_count != 0u) {
        return vm_finish(out, AL_ERR_MALFORMED);
    }
    al_size pc = program.functions[current_function].offset;
    for (;;) {
        al_vm_insn insn;
        if (!al_vm_decode(program.code, pc, &insn)) {
            return vm_finish(out, AL_ERR_VM_TRAP);
        }
        pc += insn.len;
        status = vm_charge(&out->resources, vm_opcode_cost(config, insn.op),
                           config);
        if (status != AL_OK) {
            return vm_finish(out, status);
        }

        al_u64 lhs = 0u;
        al_u64 rhs = 0u;
        al_u64 value = 0u;
        switch (insn.op) {
        case AL_VM_STOP:
            return vm_finish(out, AL_OK);
        case AL_VM_PUSH64:
            status = vm_push(stack, &stack_size, config->stack_limit,
                             insn.immediate);
            break;
        case AL_VM_ADD: case AL_VM_SUB: case AL_VM_MUL:
        case AL_VM_DIV: case AL_VM_MOD: case AL_VM_EQ: case AL_VM_LT:
        case AL_VM_GT: case AL_VM_LE: case AL_VM_GE: case AL_VM_AND:
        case AL_VM_OR: case AL_VM_XOR: case AL_VM_SHL: case AL_VM_SHR:
            status = vm_pop(stack, &stack_size, &rhs);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if ((insn.op == AL_VM_DIV || insn.op == AL_VM_MOD) && rhs == 0u) {
                status = AL_ERR_DIVIDE_BY_ZERO;
                break;
            }
            if (insn.op == AL_VM_ADD && al_add_overflow_u64(lhs, rhs, &value))
                status = AL_ERR_ARITH_OVERFLOW;
            else if (insn.op == AL_VM_SUB && al_sub_overflow_u64(lhs, rhs, &value))
                status = AL_ERR_ARITH_OVERFLOW;
            else if (insn.op == AL_VM_MUL && al_mul_overflow_u64(lhs, rhs, &value))
                status = AL_ERR_ARITH_OVERFLOW;
            else {
                switch ((al_u32)insn.op) {
                case AL_VM_DIV: value = lhs / rhs; break;
                case AL_VM_MOD: value = lhs % rhs; break;
                case AL_VM_EQ: value = (lhs == rhs); break;
                case AL_VM_LT: value = (lhs < rhs); break;
                case AL_VM_GT: value = (lhs > rhs); break;
                case AL_VM_LE: value = (lhs <= rhs); break;
                case AL_VM_GE: value = (lhs >= rhs); break;
                case AL_VM_AND: value = lhs & rhs; break;
                case AL_VM_OR: value = lhs | rhs; break;
                case AL_VM_XOR: value = lhs ^ rhs; break;
                case AL_VM_SHL: value = (rhs >= 64u) ? 0u : lhs << rhs; break;
                case AL_VM_SHR: value = (rhs >= 64u) ? 0u : lhs >> rhs; break;
                default: break;
                }
            }
            if (status == AL_OK)
                status = vm_push(stack, &stack_size, config->stack_limit, value);
            break;
        case AL_VM_NOT:
            status = vm_pop(stack, &stack_size, &value);
            if (status == AL_OK)
                status = vm_push(stack, &stack_size, config->stack_limit,
                                 ~value);
            break;
        case AL_VM_DUP:
            if (stack_size == 0u) status = AL_ERR_VM_TRAP;
            else status = vm_push(stack, &stack_size, config->stack_limit,
                                  stack[stack_size - 1u]);
            break;
        case AL_VM_DROP:
            status = vm_pop(stack, &stack_size, &value); break;
        case AL_VM_SWAP:
            if (stack_size < 2u) status = AL_ERR_VM_TRAP;
            else {
                value = stack[stack_size - 1u];
                stack[stack_size - 1u] = stack[stack_size - 2u];
                stack[stack_size - 2u] = value;
                status = AL_OK;
            }
            break;
        case AL_VM_JUMP:
            pc = (al_size)insn.immediate; status = AL_OK; break;
        case AL_VM_JUMPI:
            status = vm_pop(stack, &stack_size, &value);
            if (status == AL_OK && value != 0u) pc = (al_size)insn.immediate;
            break;
        case AL_VM_LOAD8: case AL_VM_LOAD64: case AL_VM_MLOAD:
            status = vm_pop(stack, &stack_size, &value);
            if (status != AL_OK) break;
            if (value >= config->memory_limit ||
                (insn.op == AL_VM_LOAD64 &&
                 (config->memory_limit < 8u ||
                  value > config->memory_limit - 8u))) {
                status = AL_ERR_MEMORY_FAULT;
            } else {
                vm_touch_memory(&out->resources, value,
                                (insn.op == AL_VM_LOAD8) ? 1u : 8u);
                value = (insn.op == AL_VM_LOAD8)
                            ? memory[value] : al_load_le64(memory + value);
                status = vm_push(stack, &stack_size, config->stack_limit, value);
            }
            break;
        case AL_VM_STORE8: case AL_VM_STORE64: case AL_VM_MSTORE:
            status = vm_pop(stack, &stack_size, &rhs);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if (rhs >= config->memory_limit ||
                (insn.op == AL_VM_STORE64 &&
                 (config->memory_limit < 8u ||
                  rhs > config->memory_limit - 8u))) {
                status = AL_ERR_MEMORY_FAULT;
            } else if (insn.op == AL_VM_STORE8) {
                vm_touch_memory(&out->resources, rhs, 1u);
                memory[rhs] = (al_u8)lhs; status = AL_OK;
            } else {
                vm_touch_memory(&out->resources, rhs, 8u);
                al_store_le64(memory + rhs, lhs); status = AL_OK;
            }
            break;
        case AL_VM_CALLDATA_SIZE:
            status = vm_push(stack, &stack_size, config->stack_limit,
                             calldata.len); break;
        case AL_VM_CALLDATA_COPY: {
            al_u64 length = 0u, destination = 0u, source = 0u;
            status = vm_pop(stack, &stack_size, &length);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &destination);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &source);
            if (status == AL_OK &&
                (source > calldata.len || length > calldata.len - (al_size)source ||
                 destination > config->memory_limit ||
                 length > config->memory_limit - (al_size)destination)) {
                status = AL_ERR_MEMORY_FAULT;
            }
            if (status == AL_OK && length != 0u) {
                vm_touch_memory(&out->resources, destination, length);
                al_memcpy(memory + destination, calldata.data + source,
                          (al_size)length);
            }
            break;
        }
        case AL_VM_CALL: {
            al_size target = (al_size)insn.immediate;
            const al_vm_function *callee = &program.functions[target];
            if (frame_count == config->call_depth_limit ||
                stack_size < callee->parameter_count) {
                status = (frame_count == config->call_depth_limit)
                             ? AL_ERR_CALL_DEPTH : AL_ERR_VM_TRAP;
            } else {
                frames[frame_count].return_pc = pc;
                frames[frame_count].function_index = current_function;
                frames[frame_count].stack_base =
                    stack_size - callee->parameter_count;
                ++frame_count;
                current_function = target;
                pc = callee->offset;
                status = AL_OK;
            }
            break;
        }
        case AL_VM_RET: {
            if (frame_count == 0u) {
                if (stack_size == program.functions[current_function].result_count)
                    return vm_finish(out, AL_OK);
                status = AL_ERR_VM_TRAP; break;
            }
            vm_frame frame = frames[--frame_count];
            if (stack_size != frame.stack_base +
                              program.functions[current_function].result_count) {
                status = AL_ERR_VM_TRAP;
                break;
            }
            pc = frame.return_pc;
            current_function = frame.function_index;
            status = AL_OK;
            break;
        }
        case AL_VM_HOST: {
            al_size argument_count = 0u, result_count = 0u;
            status = al_vm_host_shape((al_vm_host_id)insn.immediate,
                                   &argument_count, &result_count);
            if (status != AL_OK || host == NULL || host->invoke == NULL ||
                stack_size < argument_count) {
                status = (status != AL_OK) ? status : AL_ERR_UNSUPPORTED;
                break;
            }
            status = vm_charge(&out->resources,
                               vm_host_cost(config,
                                   (al_vm_host_id)insn.immediate), config);
            if (status != AL_OK) break;
            al_u64 arguments[6] = { 0u };
            al_u64 results[2] = { 0u };
            for (al_size i = argument_count; status == AL_OK && i-- > 0u;)
                status = vm_pop(stack, &stack_size, &arguments[i]);
            if (status != AL_OK) break;
            al_vm_host_io io;
            io.arguments = arguments;
            io.argument_count = argument_count;
            io.results = results;
            io.result_capacity = result_count;
            io.result_count = 0u;
            io.memory.data = memory;
            io.memory.len = config->memory_limit;
            io.execution = &local_execution;
            io.arena = arena;
            io.resources = &out->resources;
            status = host->invoke(host->context,
                                  (al_vm_host_id)insn.immediate, &io);
            if (status == AL_OK && io.result_count != result_count)
                status = AL_ERR_VM_TRAP;
            if (status == AL_OK &&
                !al_resources_within(out->resources, config->resource_limit))
                status = AL_ERR_RESOURCE_LIMIT;
            for (al_size i = 0u; status == AL_OK && i < result_count; ++i)
                status = vm_push(stack, &stack_size, config->stack_limit,
                                 results[i]);
            break;
        }
        case AL_VM_RETURN: case AL_VM_REVERT:
            status = vm_pop(stack, &stack_size, &rhs);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status == AL_OK)
                vm_touch_memory(&out->resources, lhs, rhs);
            if (status == AL_OK &&
                !al_resources_within(out->resources, config->resource_limit))
                return vm_finish(out, AL_ERR_RESOURCE_LIMIT);
            if (status == AL_OK)
                return vm_return_data(out, arena, memory, config->memory_limit,
                                      lhs, rhs,
                                      (insn.op == AL_VM_REVERT)
                                          ? AL_ERR_REVERTED : AL_OK);
            break;
        /* ISA v2 extensions */
        case AL_VM_ISZERO:
            status = vm_pop(stack, &stack_size, &value);
            if (status == AL_OK)
                status = vm_push(stack, &stack_size, config->stack_limit,
                                 (value == 0u) ? 1u : 0u);
            break;
        case AL_VM_BYTE: {
            al_u64 position = 0u;
            status = vm_pop(stack, &stack_size, &rhs);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status == AL_OK) {
                position = lhs;
                if (position >= 8u) {
                    value = 0u;
                } else {
                    value = (rhs >> ((7u - position) * 8u)) & 0xffu;
                }
                status = vm_push(stack, &stack_size, config->stack_limit, value);
            }
            break;
        }
        case AL_VM_SIGNEXTEND: {
            al_u64 bytes_arg = 0u;
            status = vm_pop(stack, &stack_size, &rhs);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status == AL_OK) {
                bytes_arg = lhs;
                value = rhs;
                if (bytes_arg < 8u) {
                    al_u64 sign_bit_pos = bytes_arg * 8u + 7u;
                    al_u64 sign_bit = UINT64_C(1) << sign_bit_pos;
                    al_u64 mask = (sign_bit_pos < 63u)
                                      ? (UINT64_MAX << (sign_bit_pos + 1u))
                                      : 0u;
                    if (value & sign_bit) {
                        value |= mask;
                    } else {
                        value &= ~mask;
                    }
                }
                status = vm_push(stack, &stack_size, config->stack_limit, value);
            }
            break;
        }
        case AL_VM_SHA3: {
            al_u64 offset = 0u, length = 0u;
            status = vm_pop(stack, &stack_size, &length);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &offset);
            if (status != AL_OK) break;
            if (offset > config->memory_limit ||
                length > config->memory_limit - (al_size)offset) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            vm_touch_memory(&out->resources, offset, length);
            al_hash256 hash;
            al_sha256(memory + (al_size)offset, (al_size)length, &hash);
            if (offset + AL_HASH_SIZE > config->memory_limit) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            vm_touch_memory(&out->resources, offset, AL_HASH_SIZE);
            al_memcpy(memory + (al_size)offset, hash.bytes, AL_HASH_SIZE);
            status = vm_push(stack, &stack_size, config->stack_limit,
                             AL_HASH_SIZE);
            break;
        }
        case AL_VM_SLOAD: {
            al_u64 key_len = 0u;
            status = vm_pop(stack, &stack_size, &key_len);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if (lhs > config->memory_limit ||
                key_len > config->memory_limit - (al_size)lhs) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            if (local_execution.state_txn == NULL) {
                status = AL_ERR_UNSUPPORTED;
                break;
            }
            vm_touch_memory(&out->resources, lhs, key_len);
            al_bytes key = al_bytes_make(memory + (al_size)lhs, (al_size)key_len);
            al_bytes value_bytes;
            al_status sload_status = al_state_txn_storage_get(
                local_execution.state_txn,
                &local_execution.current_contract,
                key, arena, &value_bytes);
            if (sload_status == AL_ERR_NOT_FOUND) {
                status = vm_push(stack, &stack_size, config->stack_limit,
                                 UINT64_MAX);
            } else if (sload_status != AL_OK) {
                status = sload_status;
            } else {
                status = vm_push(stack, &stack_size, config->stack_limit,
                                 value_bytes.len);
            }
            break;
        }
        case AL_VM_SSTORE: {
            al_u64 val_len = 0u, val_off = 0u, key_len = 0u;
            status = vm_pop(stack, &stack_size, &val_len);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &val_off);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &key_len);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if (lhs > config->memory_limit ||
                key_len > config->memory_limit - (al_size)lhs ||
                val_off > config->memory_limit ||
                val_len > config->memory_limit - (al_size)val_off) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            if (local_execution.state_txn == NULL) {
                status = AL_ERR_UNSUPPORTED;
                break;
            }
            vm_touch_memory(&out->resources, lhs, key_len);
            vm_touch_memory(&out->resources, val_off, val_len);
            al_bytes key = al_bytes_make(memory + (al_size)lhs, (al_size)key_len);
            al_bytes val = al_bytes_make(memory + (al_size)val_off, (al_size)val_len);
            status = al_state_txn_storage_set(
                local_execution.state_txn,
                &local_execution.current_contract, key, val);
            break;
        }
        case AL_VM_ADDRESS: {
            status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if (lhs + AL_ADDRESS_SIZE > config->memory_limit) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            vm_touch_memory(&out->resources, lhs, AL_ADDRESS_SIZE);
            al_memcpy(memory + (al_size)lhs,
                      local_execution.current_contract.bytes, AL_ADDRESS_SIZE);
            break;
        }
        case AL_VM_CALLER: {
            status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if (lhs + AL_ADDRESS_SIZE > config->memory_limit) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            vm_touch_memory(&out->resources, lhs, AL_ADDRESS_SIZE);
            al_memcpy(memory + (al_size)lhs,
                      local_execution.sender.bytes, AL_ADDRESS_SIZE);
            break;
        }
        case AL_VM_CALLVALUE:
            status = vm_push(stack, &stack_size, config->stack_limit,
                             local_execution.value);
            break;
        case AL_VM_CODESIZE:
            status = vm_push(stack, &stack_size, config->stack_limit,
                             local_execution.code.len);
            break;
        case AL_VM_CODECOPY: {
            al_u64 len = 0u, src = 0u;
            status = vm_pop(stack, &stack_size, &len);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &src);
            if (status == AL_OK) status = vm_pop(stack, &stack_size, &lhs);
            if (status != AL_OK) break;
            if (src > local_execution.code.len ||
                len > local_execution.code.len - (al_size)src ||
                lhs > config->memory_limit ||
                len > config->memory_limit - (al_size)lhs) {
                status = AL_ERR_MEMORY_FAULT;
                break;
            }
            vm_touch_memory(&out->resources, lhs, len);
            if (len != 0u) {
                al_memcpy(memory + (al_size)lhs,
                          local_execution.code.data + (al_size)src,
                          (al_size)len);
            }
            break;
        }
        case AL_VM_OPCODE_SENTINEL:
            status = AL_ERR_INVALID_OPCODE; break;
        }
        if (status != AL_OK) {
            return vm_finish(out, status);
        }
    }
}

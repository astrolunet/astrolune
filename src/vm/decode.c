/*
 * ALVM instruction decoding, stack-effect analysis and program validation.
 *
 * Split from vm.c to keep the interpreter loop, the container format and the
 * static analysis separate. Everything here is pure: no allocation, no state
 * mutation beyond the caller-supplied scratch arena in vm_validate_program.
 */

#include "astrolune/vm.h"
#include "internal.h"
#include "internal/common.h"

#include <stdio.h>

/* --------------------------------------------------------------------------
 * Instruction decode
 * -------------------------------------------------------------------------- */

al_bool al_vm_decode(al_bytes code, al_size position, al_vm_insn *out) {
    if (out == NULL || position >= code.len) {
        return AL_FALSE;
    }
    out->op = (al_vm_opcode)code.data[position];
    out->len = 1u;
    out->immediate = 0u;

    if (out->op == AL_VM_PUSH64) {
        out->len = 9u;
        if (code.len - position < out->len) {
            return AL_FALSE;
        }
        out->immediate = al_load_le64(code.data + position + 1u);
    } else if (out->op == AL_VM_JUMP || out->op == AL_VM_JUMPI) {
        out->len = 5u;
        if (code.len - position < out->len) {
            return AL_FALSE;
        }
        out->immediate = al_load_le32(code.data + position + 1u);
    } else if (out->op == AL_VM_CALL || out->op == AL_VM_HOST) {
        out->len = 3u;
        if (code.len - position < out->len) {
            return AL_FALSE;
        }
        out->immediate = al_load_le16(code.data + position + 1u);
    }
    return AL_TRUE;
}

/* --------------------------------------------------------------------------
 * Opcode classification
 * -------------------------------------------------------------------------- */

al_bool al_vm_opcode_valid(al_vm_opcode op) {
    return (op >= AL_VM_STOP && op <= AL_VM_HOST) ||
           (op >= AL_VM_ISZERO && op <= AL_VM_CODECOPY) ? AL_TRUE : AL_FALSE;
}

al_bool al_vm_terminal(al_vm_opcode op) {
    return (op == AL_VM_STOP || op == AL_VM_RETURN || op == AL_VM_REVERT ||
            op == AL_VM_RET) ? AL_TRUE : AL_FALSE;
}

/* --------------------------------------------------------------------------
 * Host function shapes
 * -------------------------------------------------------------------------- */

al_status al_vm_host_shape(al_vm_host_id id, al_size *arguments,
                           al_size *results) {
    if (arguments == NULL || results == NULL) {
        return AL_ERR_INVALID_ARG;
    }
    switch (id) {
    case AL_VM_HOST_SENDER:
    case AL_VM_HOST_CURRENT_ADDRESS:
        *arguments = 1u; *results = 0u; return AL_OK;
    case AL_VM_HOST_BLOCK_HEIGHT:
    case AL_VM_HOST_PROTOCOL_DAY:
        *arguments = 0u; *results = 1u; return AL_OK;
    case AL_VM_HOST_BALANCE:
        *arguments = 1u; *results = 1u; return AL_OK;
    case AL_VM_HOST_TRANSFER:
    case AL_VM_HOST_STORAGE_DELETE:
        *arguments = 2u; *results = 0u; return AL_OK;
    case AL_VM_HOST_STORAGE_GET:
    case AL_VM_HOST_STORAGE_SET:
    case AL_VM_HOST_EMIT_EVENT:
    case AL_VM_HOST_HASH_TAGGED:
        *arguments = 4u; *results = (id == AL_VM_HOST_STORAGE_GET) ? 1u : 0u;
        return AL_OK;
    case AL_VM_HOST_VERIFY_SIGNATURE:
        *arguments = 3u; *results = 1u; return AL_OK;
    case AL_VM_HOST_CALL_CONTRACT:
        *arguments = 6u; *results = 2u; return AL_OK;
    case AL_VM_HOST_ID_SENTINEL:
        break;
    }
    return AL_ERR_UNSUPPORTED;
}

/* --------------------------------------------------------------------------
 * Stack-effect analysis
 * -------------------------------------------------------------------------- */

al_status al_vm_stack_effect(const al_vm_program *program,
                             const al_vm_insn *insn,
                             al_size *pops, al_size *pushes) {
    *pops = 0u;
    *pushes = 0u;
    switch (insn->op) {
    case AL_VM_STOP:
    case AL_VM_JUMP:
    case AL_VM_RET:
        return AL_OK;
    case AL_VM_PUSH64:
    case AL_VM_CALLDATA_SIZE:
        *pushes = 1u; return AL_OK;
    case AL_VM_ADD: case AL_VM_SUB: case AL_VM_MUL: case AL_VM_DIV:
    case AL_VM_MOD: case AL_VM_EQ: case AL_VM_LT: case AL_VM_GT:
    case AL_VM_LE: case AL_VM_GE: case AL_VM_AND: case AL_VM_OR:
    case AL_VM_XOR: case AL_VM_SHL: case AL_VM_SHR:
        *pops = 2u; *pushes = 1u; return AL_OK;
    case AL_VM_NOT:
    case AL_VM_LOAD8:
    case AL_VM_LOAD64:
        *pops = 1u; *pushes = 1u; return AL_OK;
    case AL_VM_DUP:
        *pops = 1u; *pushes = 2u; return AL_OK;
    case AL_VM_DROP:
    case AL_VM_JUMPI:
        *pops = 1u; return AL_OK;
    case AL_VM_SWAP:
        *pops = 2u; *pushes = 2u; return AL_OK;
    case AL_VM_STORE8:
    case AL_VM_STORE64:
    case AL_VM_RETURN:
    case AL_VM_REVERT:
        *pops = 2u; return AL_OK;
    case AL_VM_CALLDATA_COPY:
        *pops = 3u; return AL_OK;
    case AL_VM_CALL:
        if (insn->immediate >= program->function_count) {
            return AL_ERR_MALFORMED;
        }
        *pops = program->functions[insn->immediate].parameter_count;
        *pushes = program->functions[insn->immediate].result_count;
        return AL_OK;
    case AL_VM_HOST:
        return al_vm_host_shape((al_vm_host_id)insn->immediate, pops, pushes);
    /* ISA v2 extensions */
    case AL_VM_ISZERO:
        *pops = 1u; *pushes = 1u; return AL_OK;
    case AL_VM_CALLVALUE:
    case AL_VM_CODESIZE:
        *pushes = 1u; return AL_OK;
    case AL_VM_MLOAD:
        *pops = 1u; *pushes = 1u; return AL_OK;
    case AL_VM_BYTE:
    case AL_VM_SIGNEXTEND:
    case AL_VM_SHA3:
    case AL_VM_SLOAD:
        *pops = 2u; *pushes = 1u; return AL_OK;
    case AL_VM_SSTORE:
        *pops = 4u; return AL_OK;
    case AL_VM_MSTORE:
        *pops = 2u; return AL_OK;
    case AL_VM_CODECOPY:
        *pops = 3u; return AL_OK;
    case AL_VM_ADDRESS:
    case AL_VM_CALLER:
        *pops = 1u; return AL_OK;
    case AL_VM_OPCODE_SENTINEL:
        break;
    }
    return AL_ERR_INVALID_OPCODE;
}

/* --------------------------------------------------------------------------
 * Program validation (static analysis)
 * -------------------------------------------------------------------------- */

static al_status vm_queue_successor(al_u64 *heights, al_u32 *queue,
                                    al_size *tail, al_size successor,
                                    al_u64 height) {
    if (heights[successor] == UINT64_MAX) {
        heights[successor] = height;
        queue[(*tail)++] = (al_u32)successor;
        return AL_OK;
    }
    return (heights[successor] == height) ? AL_OK : AL_ERR_MALFORMED;
}

al_status al_vm_validate_program(const al_vm_program *program,
                                 const al_vm_config *config,
                                 al_arena *scratch) {
    if (program == NULL || config == NULL || scratch == NULL ||
        config->stack_limit == 0u || config->memory_limit == 0u ||
        config->call_depth_limit == 0u) {
        return AL_ERR_INVALID_ARG;
    }
    if (config->schedule != NULL) {
        for (al_size i = 0u; i < AL_VM_OPCODE_COUNT; ++i) {
            if (config->schedule->opcode[i] == 0u ||
                config->schedule->opcode[i] == UINT64_MAX)
                return AL_ERR_INVALID_ARG;
        }
        for (al_size i = 0u; i < AL_VM_HOST_COUNT; ++i) {
            if (config->schedule->host[i] == 0u ||
                config->schedule->host[i] == UINT64_MAX)
                return AL_ERR_INVALID_ARG;
        }
    }
    al_u8 *boundaries = (al_u8 *)al_arena_calloc(
        scratch, program->code.len + 1u, sizeof(*boundaries));
    al_u64 *heights = AL_ARENA_NEW_ARRAY(scratch, al_u64,
                                         program->code.len + 1u);
    al_u32 *queue = AL_ARENA_NEW_ARRAY(scratch, al_u32,
                                       program->code.len + 1u);
    al_u8 *call_targets = (al_u8 *)al_arena_calloc(
        scratch, program->function_count, sizeof(*call_targets));
    if (boundaries == NULL || heights == NULL || queue == NULL ||
        call_targets == NULL) {
        return AL_ERR_OUT_OF_MEMORY;
    }

    for (al_size position = 0u; position < program->code.len;) {
        al_vm_insn insn;
        if (!al_vm_decode(program->code, position, &insn)) {
            return AL_ERR_MALFORMED;
        }
        if (!al_vm_opcode_valid(insn.op)) {
            return AL_ERR_INVALID_OPCODE;
        }
        if (insn.op == AL_VM_CALL) {
            if (insn.immediate >= program->function_count) {
                return AL_ERR_MALFORMED;
            }
            call_targets[insn.immediate] = 1u;
        }
        boundaries[position] = 1u;
        position += insn.len;
    }
    boundaries[program->code.len] = 1u;

    for (al_size index = 0u; index < program->function_count; ++index) {
        const al_vm_function *function = &program->functions[index];
        al_size start = function->offset;
        al_size end = (index + 1u < program->function_count)
                          ? program->functions[index + 1u].offset
                          : program->code.len;
        if (function->reserved != 0u || start >= end ||
            start >= program->code.len || !boundaries[start] ||
            function->max_stack < function->parameter_count ||
            function->max_stack < function->result_count ||
            function->max_stack > config->stack_limit ||
            (index == 0u && function->parameter_count != 0u) ||
            (index != 0u && start <= program->functions[index - 1u].offset)) {
            return AL_ERR_MALFORMED;
        }
        for (al_size i = start; i <= end; ++i) {
            heights[i] = UINT64_MAX;
        }
        al_size head = 0u;
        al_size tail = 0u;
        heights[start] = function->parameter_count;
        queue[tail++] = (al_u32)start;
        while (head < tail) {
            al_size position = queue[head++];
            al_vm_insn insn;
            if (!al_vm_decode(program->code, position, &insn) ||
                position + insn.len > end) {
                fprintf(stderr,
                        "DBG vfail decode idx=%zu pos=%zu end=%zu\n", index,
                        position, end);
                return AL_ERR_MALFORMED;
            }
            al_size pops = 0u;
            al_size pushes = 0u;
            AL_TRY(al_vm_stack_effect(program, &insn, &pops, &pushes));
            al_u64 height = heights[position];
            if (height < pops) {
                fprintf(stderr,
                        "DBG vfail underflow idx=%zu pos=%zu h=%llu p=%llu\n",
                        index, position, (unsigned long long)height,
                        (unsigned long long)pops);
                return AL_ERR_MALFORMED;
            }
            al_u64 next_height = height - pops + pushes;
            if (next_height > function->max_stack ||
                next_height > config->stack_limit) {
                return AL_ERR_STACK_OVERFLOW;
            }

            if (al_vm_terminal(insn.op)) {
                if (height < pops)
                    fprintf(stderr, "DBG vfail term-height idx=%zu pos=%zu\n",
                            index, position);
                if (index == 0u) {
                    if (insn.op == AL_VM_RET ||
                        function->parameter_count != 0u)
                        { fprintf(stderr, "DBG vfail f0 idx=%zu\n", index); return AL_ERR_MALFORMED; }
                } else if (call_targets[index] != 0u) {
                    if (insn.op != AL_VM_RET)
                        { fprintf(stderr, "DBG vfail callable-term idx=%zu op=%d\n", index, (int)insn.op); return AL_ERR_MALFORMED; }
                } else if (insn.op == AL_VM_RET) {
                    if (next_height != function->result_count)
                        { fprintf(stderr, "DBG vfail ret-height idx=%zu\n", index); return AL_ERR_MALFORMED; }
                } else if (function->parameter_count != 0u) {
                    { fprintf(stderr, "DBG vfail entry-params idx=%zu\n", index); return AL_ERR_MALFORMED; }
                }
                continue;
            }
            al_size fallthrough = position + insn.len;
            if (insn.op == AL_VM_JUMP || insn.op == AL_VM_JUMPI) {
                al_size target = (al_size)insn.immediate;
                if (target < start || target >= end || !boundaries[target]) {
                    return AL_ERR_MALFORMED;
                }
                AL_TRY(vm_queue_successor(heights, queue, &tail, target,
                                          next_height));
                if (insn.op == AL_VM_JUMP) {
                    continue;
                }
            }
            if (fallthrough >= end || !boundaries[fallthrough]) {
                return AL_ERR_MALFORMED;
            }
            AL_TRY(vm_queue_successor(heights, queue, &tail, fallthrough,
                                      next_height));
        }

        al_size last = start;
        for (al_size position = start; position < end;) {
            al_vm_insn insn;
            if (!al_vm_decode(program->code, position, &insn))
                return AL_ERR_MALFORMED;
            last = position;
            position += insn.len;
        }
        al_vm_insn terminator;
        if (!al_vm_decode(program->code, last, &terminator))
            return AL_ERR_MALFORMED;
        if (!al_vm_terminal(terminator.op)) {
            return AL_ERR_MALFORMED;
        }
    }
    return AL_OK;
}

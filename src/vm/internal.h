/*
 * Internal ALVM declarations shared between decode.c, container.c and
 * vm.c. Not part of the public API.
 */

#ifndef ASTROLUNE_VM_INTERNAL_H
#define ASTROLUNE_VM_INTERNAL_H

#include "astrolune/vm.h"

AL_EXTERN_C_BEGIN

/* Instruction representation (decode.c) */
typedef struct al_vm_insn {
    al_vm_opcode op;
    al_size      len;
    al_u64       immediate;
} al_vm_insn;

/* Decode one instruction at `position` in `code`. */
al_bool al_vm_decode(al_bytes code, al_size position, al_vm_insn *out);

/* Opcode classification. */
al_bool al_vm_opcode_valid(al_vm_opcode op);
al_bool al_vm_terminal(al_vm_opcode op);

/* Host function argument/result counts. */
al_status al_vm_host_shape(al_vm_host_id id, al_size *arguments,
                           al_size *results);

/* Stack-effect analysis for one instruction. */
al_status al_vm_stack_effect(const al_vm_program *program,
                             const al_vm_insn *insn,
                             al_size *pops, al_size *pushes);

/* Static program validation (boundaries, stack heights, termination). */
al_status al_vm_validate_program(const al_vm_program *program,
                                 const al_vm_config *config,
                                 al_arena *scratch);

/* Container decode (container.c). */
al_status al_vm_program_decode(al_bytes container, al_arena *arena,
                               al_vm_program *out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_VM_INTERNAL_H */

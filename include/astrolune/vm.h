/* astrolune/vm.h - canonical ALVM containers and the v1 interpreter. */

#ifndef ASTROLUNE_VM_H
#define ASTROLUNE_VM_H

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/bytes.h"

AL_EXTERN_C_BEGIN

#define AL_VM_CONTAINER_VERSION 1u
#define AL_VM_ISA_VERSION 1u
#define AL_VM_MAX_CODE_SIZE (1024u * 1024u)
#define AL_VM_MAX_FUNCTIONS 1024u
#define AL_VM_DEFAULT_STACK 1024u
#define AL_VM_DEFAULT_MEMORY (64u * 1024u)
#define AL_VM_DEFAULT_CALL_DEPTH 64u
#define AL_VM_MEMORY_PAGE_SIZE 4096u
#define AL_VM_OPCODE_COUNT 47u
#define AL_VM_HOST_COUNT 13u

typedef enum al_vm_opcode {
    AL_VM_STOP          = 0x00,
    AL_VM_PUSH64        = 0x01,
    AL_VM_ADD           = 0x02,
    AL_VM_SUB           = 0x03,
    AL_VM_MUL           = 0x04,
    AL_VM_DIV           = 0x05,
    AL_VM_EQ            = 0x06,
    AL_VM_LT            = 0x07,
    AL_VM_DUP           = 0x08,
    AL_VM_DROP          = 0x09,
    AL_VM_JUMP          = 0x0a,
    AL_VM_JUMPI         = 0x0b,
    AL_VM_LOAD8         = 0x0c,
    AL_VM_STORE8        = 0x0d,
    AL_VM_RETURN        = 0x0e,
    AL_VM_REVERT        = 0x0f,
    AL_VM_MOD           = 0x10,
    AL_VM_AND           = 0x11,
    AL_VM_OR            = 0x12,
    AL_VM_XOR           = 0x13,
    AL_VM_NOT           = 0x14,
    AL_VM_SHL           = 0x15,
    AL_VM_SHR           = 0x16,
    AL_VM_GT            = 0x17,
    AL_VM_LE            = 0x18,
    AL_VM_GE            = 0x19,
    AL_VM_SWAP          = 0x1a,
    AL_VM_LOAD64        = 0x1b,
    AL_VM_STORE64       = 0x1c,
    AL_VM_CALLDATA_SIZE = 0x1d,
    AL_VM_CALLDATA_COPY = 0x1e,
    AL_VM_CALL          = 0x1f,
    AL_VM_RET           = 0x20,
    AL_VM_HOST          = 0x21,

    /* ISA v2 extensions: utility, storage, hashing, and context opcodes. */
    AL_VM_ISZERO        = 0x22,  /* (a) -> (a==0)                          */
    AL_VM_BYTE          = 0x23,  /* (position,value) -> (byte)             */
    AL_VM_SIGNEXTEND    = 0x24,  /* (bytes,value) -> (sign-extended)       */
    AL_VM_SHA3          = 0x25,  /* (offset,length) -> (hash)              */
    AL_VM_MLOAD         = 0x26,  /* (offset) -> (u64)  load 8 bytes LE     */
    AL_VM_MSTORE        = 0x27,  /* (value,offset) -> ()  store 8 bytes LE */
    AL_VM_SLOAD         = 0x28,  /* (key_off,key_len) -> (val_len)         */
    AL_VM_SSTORE        = 0x29,  /* (key_off,key_len,val_off,val_len) ->() */
    AL_VM_ADDRESS       = 0x2a,  /* (offset) -> ()  write contract addr    */
    AL_VM_CALLER        = 0x2b,  /* (offset) -> ()  write sender addr      */
    AL_VM_CALLVALUE     = 0x2c,  /* () -> (value)                          */
    AL_VM_CODESIZE      = 0x2d,  /* () -> (size)                           */
    AL_VM_CODECOPY      = 0x2e,  /* (dest_off,src_off,len) -> ()           */

    AL_VM_OPCODE_SENTINEL = 0x7fffffff
} al_vm_opcode;

typedef enum al_vm_host_id {
    AL_VM_HOST_SENDER = 0,
    AL_VM_HOST_CURRENT_ADDRESS = 1,
    AL_VM_HOST_BLOCK_HEIGHT = 2,
    AL_VM_HOST_PROTOCOL_DAY = 3,
    AL_VM_HOST_BALANCE = 4,
    AL_VM_HOST_TRANSFER = 5,
    AL_VM_HOST_STORAGE_GET = 6,
    AL_VM_HOST_STORAGE_SET = 7,
    AL_VM_HOST_STORAGE_DELETE = 8,
    AL_VM_HOST_EMIT_EVENT = 9,
    AL_VM_HOST_HASH_TAGGED = 10,
    AL_VM_HOST_VERIFY_SIGNATURE = 11,
    AL_VM_HOST_CALL_CONTRACT = 12,
    AL_VM_HOST_ID_SENTINEL = 0x7fffffff
} al_vm_host_id;

/* Consensus-visible domains accepted by AL_VM_HOST_HASH_TAGGED. Bytecode uses
 * these stable numeric IDs rather than choosing arbitrary domain strings. */
typedef enum al_vm_hash_domain {
    AL_VM_HASH_CONTRACT_DATA = 0,
    AL_VM_HASH_ADDRESS = 1,
    AL_VM_HASH_STORAGE_KEY = 2,
    AL_VM_HASH_STORAGE_VALUE = 3,
    AL_VM_HASH_EVENT = 4,
    AL_VM_HASH_POTB_RECORD = 5,
    AL_VM_HASH_TRANSACTION = 6,
    AL_VM_HASH_BLOCK = 7,
    AL_VM_HASH_DOMAIN_SENTINEL = 0x7fffffff
} al_vm_hash_domain;

typedef struct al_vm_function {
    al_u32 offset;
    al_u16 parameter_count;
    al_u16 result_count;
    al_u16 max_stack;
    al_u16 reserved;
} al_vm_function;

typedef struct al_vm_program {
    al_bytes              container;
    al_bytes              code;
    const al_vm_function *functions;
    al_size               function_count;
    al_u16                container_version;
    al_u16                isa_version;
    al_u32                flags;
} al_vm_program;

typedef struct al_vm_resource_schedule {
    al_u64 opcode[AL_VM_OPCODE_COUNT];
    al_u64 host[AL_VM_HOST_COUNT];
} al_vm_resource_schedule;

typedef struct al_vm_config {
    al_size      stack_limit;
    al_size      memory_limit;
    al_size      call_depth_limit;
    al_resources resource_limit;
    const al_vm_resource_schedule *schedule;
} al_vm_config;

struct al_state_txn;

typedef struct al_vm_execution_context {
    al_address                 sender;
    al_address                 current_contract;
    al_height                  block_height;
    al_u32                     protocol_day;
    al_u32                     entrypoint;
    al_amount                  value;
    al_bytes                   code;
    struct al_state_txn       *state_txn;
    const al_address          *active_contracts;
    al_size                    active_contract_count;
} al_vm_execution_context;

typedef struct al_vm_host_io {
    const al_u64             *arguments;
    al_size                   argument_count;
    al_u64                   *results;
    al_size                   result_capacity;
    al_size                   result_count;
    al_bytes_mut              memory;
    const al_vm_execution_context *execution;
    al_arena                 *arena;
    al_resources             *resources;
} al_vm_host_io;

typedef al_status (*al_vm_host_invoke_fn)(void *context, al_vm_host_id id,
                                          al_vm_host_io *io);

typedef struct al_vm_host {
    void                 *context;
    al_vm_host_invoke_fn  invoke;
} al_vm_host;

typedef struct al_vm_result {
    al_status    status;
    al_resources resources;
    al_bytes     return_data;
} al_vm_result;

AL_PUBLIC al_vm_config al_vm_config_default(void);
AL_PUBLIC al_vm_resource_schedule al_vm_resource_schedule_default(void);
AL_PUBLIC al_u64 al_vm_compute_cost(al_vm_opcode opcode);
AL_PUBLIC al_u64 al_vm_host_compute_cost(al_vm_host_id id);
AL_PUBLIC AL_NODISCARD al_status al_vm_container_encode(
    const al_vm_function *functions, al_size function_count, al_bytes code,
    al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_vm_program_load(
    al_bytes container, const al_vm_config *config, al_arena *arena,
    al_vm_program *out);
AL_PUBLIC AL_NODISCARD al_status al_vm_validate(
    al_bytes container, const al_vm_config *config, al_arena *scratch);
AL_PUBLIC AL_NODISCARD al_status al_vm_execute(
    al_bytes container, al_bytes calldata, const al_vm_config *config,
    const al_vm_execution_context *execution, const al_vm_host *host,
    al_arena *arena, al_vm_result *out);

AL_EXTERN_C_END

#endif /* ASTROLUNE_VM_H */

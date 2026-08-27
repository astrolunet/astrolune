#include "astrolune/base.h"

#include "internal/common.h"

const char *al_status_str(al_status status) {
    switch (status) {
    case AL_OK:                        return "ok";

    case AL_ERR_INVALID_ARG:           return "invalid argument";
    case AL_ERR_OUT_OF_RANGE:          return "value out of range";
    case AL_ERR_BUFFER_TOO_SMALL:      return "buffer too small";
    case AL_ERR_UNSUPPORTED:           return "unsupported operation";
    case AL_ERR_NOT_FOUND:             return "not found";
    case AL_ERR_ALREADY_EXISTS:        return "already exists";

    case AL_ERR_OUT_OF_MEMORY:         return "out of memory";
    case AL_ERR_IO:                    return "i/o error";

    case AL_ERR_MALFORMED:             return "malformed encoding";
    case AL_ERR_NOT_CANONICAL:         return "non-canonical encoding";
    case AL_ERR_TRUNCATED:             return "truncated input";
    case AL_ERR_TRAILING_BYTES:        return "unexpected trailing bytes";

    case AL_ERR_BAD_SIGNATURE:         return "invalid signature";
    case AL_ERR_BAD_PROOF:             return "invalid proof";

    case AL_ERR_OUT_OF_GAS:            return "out of gas";
    case AL_ERR_VM_TRAP:               return "vm trap";
    case AL_ERR_STACK_OVERFLOW:        return "stack overflow";
    case AL_ERR_INVALID_OPCODE:        return "invalid opcode";
    case AL_ERR_DIVIDE_BY_ZERO:        return "divide by zero";
    case AL_ERR_ARITH_OVERFLOW:        return "arithmetic overflow";
    case AL_ERR_MEMORY_FAULT:          return "memory access out of bounds";
    case AL_ERR_CALL_DEPTH:            return "call depth exceeded";
    case AL_ERR_REVERTED:              return "execution reverted";
    case AL_ERR_RESOURCE_LIMIT:        return "resource limit exceeded";
    case AL_ERR_REENTRANCY:            return "contract reentrancy denied";

    case AL_ERR_INSUFFICIENT_FUNDS:    return "insufficient funds";
    case AL_ERR_BAD_NONCE:             return "invalid nonce";
    case AL_ERR_STATE_CORRUPT:         return "state corrupted";
    case AL_ERR_CONSENSUS_VIOLATION:   return "consensus rule violation";
    case AL_ERR_EXPIRED:               return "transaction expired";

    case AL_STATUS_SENTINEL:           break;
    }
    /* Reached only if a caller invents a status value. Returning a string keeps
     * the "never NULL" contract that log call sites rely on. */
    return "unknown status";
}

al_bool al_ok(al_status status) {
    return (status == AL_OK) ? AL_TRUE : AL_FALSE;
}

const char *al_version_string(void) {
    /* Assembled by the preprocessor so it cannot drift from the AL_VERSION_*
     * macros that the rest of the code compares against. */
#define AL_STR_(x) #x
#define AL_STR(x)  AL_STR_(x)
    return AL_STR(AL_VERSION_MAJOR) "." AL_STR(AL_VERSION_MINOR) "." \
           AL_STR(AL_VERSION_PATCH);
#undef AL_STR
#undef AL_STR_
}

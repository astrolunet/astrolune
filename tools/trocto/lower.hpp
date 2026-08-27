// Lowering: Trocto AST -> shared ModuleIR.
//
// Contract ABI fixed by this file (v0.2):
//
//   function 0            `__init` (constructor, if present) or `__default` STOP
//   each `pub fn`         0 parameters, result count when declared.
//                         Calldata is n*8 bytes for u64/address params, variable
//                         for string params; a short calldata reverts with code 1.
//                         Results return through RETURN.
//   each plain `fn`       VM frame protocol: stack parameters, RET.
//
// Linear-memory layout per function (static offsets, no dynamic allocation):
//
//   0..32    scratch A - state key / event topic / map key preimage
//   32..64   scratch B - second key / event data / revert code / u64 map key
//   64..72   pub-fn result slot
//   72..104  sender() materialization (32 bytes)
//   104..136 self() materialization (32 bytes)
//   136..168 derived map storage key (32 bytes)
//   168..    locals, then parameters
//
// State fields are u64 slots keyed by the contract-data tagged hash of
// "field.<contract>.<name>", embedded as push64 constants.
// Map entries are keyed by tagged_hash(contract_data, "map.<Contract>.<field>." || key_bytes).

#ifndef TROCTO_LOWER_HPP
#define TROCTO_LOWER_HPP

#include "trocto_ast.hpp"

namespace trocto {

std::optional<ModuleIR> lower_contract(const ContractDecl& contract,
                                       Diagnostics& diagnostics);

}  // namespace trocto

#endif  // TROCTO_LOWER_HPP

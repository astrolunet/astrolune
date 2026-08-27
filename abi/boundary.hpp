/*
 * Shared declarations for the boundary check executable.
 *
 * Two files need to agree on the symbol table: boundary_symbols.cpp defines it,
 * boundary_main.cpp reports it. Nothing else should include this.
 */

#ifndef ASTROLUNE_ABI_BOUNDARY_HPP
#define ASTROLUNE_ABI_BOUNDARY_HPP

#include <cstddef>

/*
 * A pointer to a function whose signature is deliberately forgotten.
 *
 * The table exists to make the linker resolve every public symbol, and for that
 * only the address matters. Keeping 221 distinct signatures would mean writing
 * every prototype out a second time, which is transcription with its own
 * opportunities to be wrong. Reinterpreting a function pointer as another
 * function pointer type is well defined; calling through the result would not
 * be, so nothing here ever calls one.
 */
using al_abi_fn = void (*)();

extern const al_abi_fn al_abi_symbols[];
extern const std::size_t al_abi_symbol_count;

#endif /* ASTROLUNE_ABI_BOUNDARY_HPP */

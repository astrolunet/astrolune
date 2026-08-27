/*
 * The C half of the layout contract.
 *
 * A .c file under cpp/ looks out of place, and the reason it is here is the
 * reason the check works at all: a comparison between two languages cannot live
 * in only one of them. The v1 abi_contract.h asserts literals; this file makes
 * the C compiler evaluate them and contract_cxx.cpp makes the C++ compiler
 * evaluate the same ones. Only both together say the two agree.
 *
 * Putting it in tests/ instead would have been the wrong place twice over: it is
 * not a test (it produces no result and cannot fail at runtime), and it belongs
 * next to the C++ file it is paired with, since editing one without the other
 * destroys the property.
 *
 * The translation unit is deliberately empty of definitions. C requires a
 * translation unit to contain at least one declaration, and each assertion in
 * the header is one, so this is well formed with no linker symbol at all.
 */

#include "abi_contract.h"

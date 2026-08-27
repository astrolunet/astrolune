/*
 * All eleven public headers in one C++ translation unit, included twice.
 *
 * This asks two questions the per-header translation units cannot.
 *
 * Do the headers collide? Sharing one TU is what a real tool does, and it is
 * where a macro defined differently in two headers, or a type declared in two
 * of them, becomes an error rather than a coincidence.
 *
 * Are the include guards right? The second pass is what checks them. A header
 * with a missing, misspelled or copy-pasted guard - the same ASTROLUNE_*_H used
 * by two files is the usual version of this mistake - fails here with a
 * redefinition, and would otherwise fail in whichever downstream tool first
 * happened to include two headers along two paths.
 *
 * tests/c/test_cpp_headers.cpp is the minimal ancestor of this file: eleven
 * includes and an empty main. It is kept because it is nearly free, but every
 * check it performs is a subset of this one.
 */

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/fixed.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/vm.h"

/* Second pass. Every one of these must expand to nothing. */
#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/block.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/fixed.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/vm.h"

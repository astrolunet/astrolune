/* Does astrolune/tx.h compile as C++ on its own? See header_base.cpp.
 *
 * The only public header that depends on another non-base one (state.h, for
 * al_state in al_tx_apply), so it is the one where a forgotten include would
 * actually have been possible. */

#include "astrolune/tx.h"

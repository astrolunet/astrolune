/*
 * OS-provided cryptographically secure random bytes.
 *
 * Used exactly once per daemon: generating the proposer seed when no key file
 * exists yet. Everything else in Astrolune is deliberately deterministic, so
 * this is the only consumer.
 */

#ifndef ASTROLUNE_DAEMON_RANDOM_H
#define ASTROLUNE_DAEMON_RANDOM_H

#include "astrolune/base.h"

AL_EXTERN_C_BEGIN

/* Fill `buffer` with `length` unpredictable bytes. AL_FALSE means the
 * platform entropy source was unavailable; callers must refuse to proceed
 * rather than fall back to anything weaker. */
AL_NODISCARD al_bool os_random_bytes(void *buffer, al_size length);

AL_EXTERN_C_END

#endif /* ASTROLUNE_DAEMON_RANDOM_H */

/*
 * Structured logging for Astrolune.
 *
 * Levels: TRACE < DEBUG < INFO < WARN < ERROR < FATAL.
 * Each log call includes a timestamp, level tag, and module prefix.
 * Thread-safe via a global spinlock. The global level filter is atomic.
 */

#ifndef ASTROLUNE_LOG_H
#define ASTROLUNE_LOG_H

#include "astrolune/base.h"

AL_EXTERN_C_BEGIN

typedef enum al_log_level {
    AL_LOG_TRACE = 0,
    AL_LOG_DEBUG,
    AL_LOG_INFO,
    AL_LOG_WARN,
    AL_LOG_ERROR,
    AL_LOG_FATAL,
    AL_LOG_SILENT,   /* disables all logging */
    AL_LOG_LEVEL_SENTINEL = 0x7fffffff
} al_log_level;

/* Set the global log level. Messages below this level are dropped. */
void al_log_set_level(al_log_level level);

/* Get the current global log level. */
al_log_level al_log_get_level(void);

/* Core logging function. Prefer the macros below. */
void al_log_write(al_log_level level, const char *module,
                  const char *fmt, ...)
#if defined(AL_COMPILER_GCC) || defined(AL_COMPILER_CLANG)
    __attribute__((format(printf, 3, 4)))
#endif
;

/* Shutdown the logging subsystem (flushes output). */
void al_log_shutdown(void);

/* --------------------------------------------------------------------------
 * Convenience macros
 *
 * Usage:  AL_LOG_INFO("net", "connected to %s:%u", host, port);
 * -------------------------------------------------------------------------- */

#define AL_LOG_TRACE(mod, ...) \
    al_log_write(AL_LOG_TRACE, (mod), __VA_ARGS__)
#define AL_LOG_DEBUG(mod, ...) \
    al_log_write(AL_LOG_DEBUG, (mod), __VA_ARGS__)
#define AL_LOG_INFO(mod, ...) \
    al_log_write(AL_LOG_INFO, (mod), __VA_ARGS__)
#define AL_LOG_WARN(mod, ...) \
    al_log_write(AL_LOG_WARN, (mod), __VA_ARGS__)
#define AL_LOG_ERROR(mod, ...) \
    al_log_write(AL_LOG_ERROR, (mod), __VA_ARGS__)
#define AL_LOG_FATAL(mod, ...) \
    al_log_write(AL_LOG_FATAL, (mod), __VA_ARGS__)

AL_EXTERN_C_END

#endif /* ASTROLUNE_LOG_H */

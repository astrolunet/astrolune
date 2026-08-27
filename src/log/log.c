/* Structured logging implementation. See log.h for the public API. */

#include "astrolune/log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#if defined(AL_OS_WINDOWS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
static CRITICAL_SECTION g_log_lock;
static al_bool g_log_lock_init;
static void log_lock(void) {
    if (!g_log_lock_init) { InitializeCriticalSection(&g_log_lock); g_log_lock_init = AL_TRUE; }
    EnterCriticalSection(&g_log_lock);
}
static void log_unlock(void) { LeaveCriticalSection(&g_log_lock); }
#else
#  include <pthread.h>
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static void log_lock(void)   { pthread_mutex_lock(&g_log_lock); }
static void log_unlock(void) { pthread_mutex_unlock(&g_log_lock); }
#endif

static al_log_level g_log_level = AL_LOG_INFO;
static FILE        *g_log_file  = NULL; /* NULL = stderr */

static const char *level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "SILENT"
};

static const char *level_colors[] = {
    "\033[36m",  /* TRACE: cyan */
    "\033[35m",  /* DEBUG: magenta */
    "\033[32m",  /* INFO: green */
    "\033[33m",  /* WARN: yellow */
    "\033[31m",  /* ERROR: red */
    "\033[35;1m", /* FATAL: bright magenta */
    "",          /* SILENT */
};

#define RESET_COLOR "\033[0m"

void al_log_set_level(al_log_level level) {
    g_log_level = level;
}

al_log_level al_log_get_level(void) {
    return g_log_level;
}

void al_log_write(al_log_level level, const char *module,
                  const char *fmt, ...) {
    if (level < g_log_level || level >= AL_LOG_SILENT) return;

    log_lock();

    FILE *out = g_log_file ? g_log_file : stderr;

    /* Timestamp: YYYY-MM-DD HH:MM:SS */
    time_t now = time(NULL);
    struct tm tm_buf;
#if defined(AL_OS_WINDOWS)
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    /* Use color on stderr, plain on files. */
    if (!g_log_file) {
        fprintf(out, "%s%s%-5s%s [%s] ",
                level_colors[level], time_str, level_names[level],
                RESET_COLOR, module);
    } else {
        fprintf(out, "%s %-5s [%s] ", time_str, level_names[level], module);
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);

    log_unlock();
}

void al_log_shutdown(void) {
    log_lock();
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    log_unlock();
}

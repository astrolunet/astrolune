/*
 * TOML config file loader for the Astrolune daemon.
 *
 * Reads a TOML file and populates al_daemon_config. CLI flags override
 * config file values. Config file provides defaults; CLI is authoritative.
 */

#ifndef ASTROLUNE_DAEMON_CONFIG_H
#define ASTROLUNE_DAEMON_CONFIG_H

#include "daemon.h"
#include "astrolune/toml.h"

AL_EXTERN_C_BEGIN

/* Load configuration from a TOML file into `config`.
 * Fields already set by CLI flags (non-NULL / non-zero) are NOT overwritten.
 * Returns AL_OK on success. */
AL_NODISCARD al_status al_daemon_config_load(const char *path,
                                              al_daemon_config *config);

/* Load configuration from a TOML text buffer. */
AL_NODISCARD al_status al_daemon_config_load_memory(const char *text,
                                                     al_size len,
                                                     al_daemon_config *config);

AL_EXTERN_C_END

#endif /* ASTROLUNE_DAEMON_CONFIG_H */

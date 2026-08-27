# Structured logging.

astrolune_add_core_library(al_log
    SOURCES log.c
    DEPS al_base
)
add_library(Astrolune::log ALIAS al_log)
target_include_directories(al_log PUBLIC "${PROJECT_SOURCE_DIR}/src/log")

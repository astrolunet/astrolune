# The alnode executable. Links the whole daemon stack so `alnode run` is a
# complete network participant; offline subcommands simply never touch it.

astrolune_add_executable(alnode
    SOURCES alnode/main.c
    DEPS al_daemon
)

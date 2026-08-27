# Astrolune

[![CI](https://github.com/astrolunet/astrolune/actions/workflows/ci.yml/badge.svg)](https://github.com/astrolunet/astrolune/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/astrolunet/astrolune)](https://github.com/astrolunet/astrolune/releases/latest)
[![Documentation](https://img.shields.io/badge/docs-online-0A7B83.svg)](https://landing-one-virid-56.vercel.app/docs)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![C23](https://img.shields.io/badge/C-23-00599C.svg)](https://en.cppreference.com/w/c/23)

Astrolune is a deterministic blockchain implementation in C23 with a small
contract VM, the Trocto contract compiler, append-only node storage, TCP gossip,
PoTB validator finality and a JSON-RPC interface for controlled networks.

The complete blockchain documentation is available at
[landing-one-virid-56.vercel.app/docs](https://landing-one-virid-56.vercel.app/docs).

> **Controlled-network release.** The validator path uses configured PoTB
> committees, signed proposals, PREVOTE/PRECOMMIT quorum and durable finality.
> The default cryptographic backend remains explicitly gated; use the sodium
> build for Ed25519 and keep validator RPC/P2P binds restricted to your network.

## Highlights

- deterministic C23 consensus core, sparse Merkle state and resource-metered VM;
- signed PoTB proposals, PREVOTE/PRECOMMIT quorum and durable certificates;
- restart-safe anti-double-sign journal and checksummed append-only storage;
- TCP transaction/finality gossip with paged catch-up and bounded peer state;
- Trocto contract compiler, JSON-RPC node and multi-validator process tests;
- strict GCC/Clang/MSVC, ASan/UBSan, libsodium, fuzz and determinism CI jobs.

## Build

Requirements: CMake 3.25+, Ninja, and a C23/C++23 compiler.

```powershell
cmake --preset dev
cmake --build --preset dev
ctest --preset dev --output-on-failure
```

The strict CI configuration can be built with `scripts\\build.bat ci test` on
Windows. Sanitiser and fuzz presets are available in `CMakePresets.json`.

The repository also includes two process-level consensus checks:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1 -Preset ci
powershell -ExecutionPolicy Bypass -File scripts\consensus-smoke.ps1 -Preset ci
```

The second scenario configures four validators and verifies both sides of the
quorum boundary: three validators finalize while two do not.

## Run a local node

Create a genesis file with the CLI, then run a single producer on loopback:

```powershell
.\\build\\dev\\bin\\alnode.exe init-genesis .\\genesis.bin
.\\build\\dev\\bin\\alnode.exe run .\\genesis.bin `
  --datadir .\\node-a `
  --p2p 127.0.0.1:44001 `
  --rpc 127.0.0.1:44002 `
  --interval 1000 `
  --allow-insecure-crypto
```

The development backend is gated by `--allow-insecure-crypto`. Configure one or
more validator public keys with repeatable `--validator <public-key-hex>`
options; nodes with the same list form the same deterministic committee. The
`transfer` and `stop` RPC methods require `--unsafe-rpc` and a loopback-only RPC
bind.

## Project map

- `include/astrolune/`: public C ABI and deterministic core types
- `src/`: VM, state, transactions, blocks, node, storage, networking and RPC
- `tools/`: Trocto/Regol contract compiler
- `tests/` and `fuzz/`: unit, integration and decoder coverage
- `AUDIT.md`: current limitations and readiness boundary

See `CONTRIBUTING.md` for the development workflow and `SECURITY.md` for
responsible vulnerability reporting.

# Astrolune

[![CI](https://github.com/astrolunet/astrolune/actions/workflows/ci.yml/badge.svg)](https://github.com/astrolunet/astrolune/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/astrolunet/astrolune)](https://github.com/astrolunet/astrolune/releases/latest)
[![Documentation](https://img.shields.io/badge/docs-GitHub-0A7B83.svg)](https://github.com/astrolunet/astrolune-docs)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![C23](https://img.shields.io/badge/C-23-00599C.svg)](https://en.cppreference.com/w/c/23)

**A blockchain written from scratch in C23 — no Rust, no Go, no external
consensus framework.** Deterministic core, BFT finality, its own contract
language, and a test suite that actually tries to break it (ASan/UBSan, fuzz,
multi-validator process tests).

```rust
// examples/counter.tc — a first Trocto contract
contract Counter {
    state {
        count: u64,
        updates: u64,
    }

    pub fn inc(by: u64) -> u64 {
        self.count += by;
        self.updates += 1;
        emit CountChanged(self.count);
        return self.count;
    }

    pub fn get() -> u64 {
        return self.count;
    }
}
```

```powershell
trocto examples/counter.tc -o counter.bin
```

Full documentation: [astrolunet/astrolune-docs](https://github.com/astrolunet/astrolune-docs) — the rendered documentation site is also available at [landing-one-virid-56.vercel.app/docs](https://landing-one-virid-56.vercel.app/docs).

**Consensus: PoTB — Proof of Trusted Behavior.** A validator's weight comes
from uptime, observed honest behaviour and its position in the trust graph —
never from hashrate or stake. See the [PoTB spec](https://landing-one-virid-56.vercel.app/en/docs/01-consensus/potb)
for the full model.

> **Controlled-network release.** This is not a public mainnet. The validator
> path uses configured PoTB committees, signed proposals, PREVOTE/PRECOMMIT
> quorum and durable finality — built for consortiums and closed networks, not
> permissionless deployment. Signatures are a development stub by default;
> the sodium build swaps in real Ed25519. VRF and VDF are not implemented or
> used by consensus; `al_crypto_is_secure()` describes the active signature
> backend only.
> See the [cryptography doc](https://landing-one-virid-56.vercel.app/en/docs/02-architecture/cryptography)
> and [AUDIT.md](AUDIT.md) for the exact readiness boundary.

## Why C23, no dependencies

Every other blockchain of this shape reaches for Rust or Go and a stack of
external crates for crypto, networking and serialization. Astrolune doesn't.
The consensus core, state machine, VM, storage engine and gossip layer are
plain C23 with a public C ABI (`include/astrolune/`) — small surface area,
easy to audit, easy to embed, no toolchain lock-in.

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

The strict CI configuration can be built with `scripts\build.bat ci test` on
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
.\build\dev\bin\alnode.exe init-genesis .\genesis.bin
.\build\dev\bin\alnode.exe run .\genesis.bin `
  --datadir .\node-a `
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
- `examples/`: sample Trocto contracts (counter, token, math)
- `tests/` and `fuzz/`: unit, integration and decoder coverage
- `AUDIT.md`: current limitations and readiness boundary

## Contributing

Look for issues labeled `good first issue`. See `CONTRIBUTING.md` for the
development workflow and `SECURITY.md` for responsible vulnerability
reporting.

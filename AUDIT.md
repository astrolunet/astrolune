# Astrolune current implementation audit

Audit date: 2026-09-02 (updated)

This is an implementation and readiness snapshot of the current source tree.
It is not a cryptographic review, a formal consensus proof, or a production
capacity assessment.

## Executive conclusion

The repository contains a coherent deterministic blockchain core and a working
signed-finality validator runtime for controlled experiments. The strict MSVC
build and all 28 registered CTest entries pass, the four-validator quorum
scenario passes, and the full two-node smoke scenario (17/17 assertions)
passes including validator restart, contract deployment/interaction, quorum
loss detection and mempool rollback.

The project is not a permissionless, material-value mainnet. The remaining
protocol, cryptographic, networking and operational boundaries below are
intentional and must remain visible.

## Implemented and verified

### Deterministic core

- C23 core types, canonical encoding, SHA-256/HMAC/HKDF and sparse Merkle state;
- resource-metered ALVM with validation, call-depth and re-entry checks;
- typed transactions with chain ID, nonce, expiry, fees, receipts and events;
- genesis allocations, block/header commitments and atomic execution;
- Trocto compiler/CLI and end-to-end contract execution tests;
- C/C++ ABI layout, linkage and public-symbol manifest checks.

### Consensus and validator runtime

- signed proposals bound to chain, parent, block, committee, height and round;
- PREVOTE/PRECOMMIT sets with unique voter membership and quorum certificates;
- isolated candidate execution: canonical state, head and mempool change only on
  finalization;
- durable finality records and restart-safe signing journal for proposal,
  prevote and precommit decisions;
- deterministic proposer rotation on round timeout and pending-transaction
  restoration after a failed round;
- on-chain validator registration with a one-block activation delay, while the
  genesis committee can still be supplied by static configuration;
- PoTB arithmetic for TBS, TGW, NDM, COD, correlation, entropy and profile-change
  metrics, plus Gini/HHI monitoring, slashing and appeal library APIs.

### Storage and recovery

- exclusive data-directory lock and permanent genesis binding;
- checksummed state, value, node, chain and finality records;
- incomplete tail truncation and fail-closed handling of complete-record
  corruption;
- synchronized durable commits with the rule that callers must reopen after an
  I/O failure;
- genesis materialization, snapshot export/import, pruning and a 64 MiB free
  space reservation before state writes.

### Network and RPC

- bounded framed TCP P2P transport with HELLO genesis binding, keepalive,
  duplicate suppression, bounded peer/outbox state and paged finalized catch-up;
- optional X25519 plus AEAD frame encryption, enabled/enforced by the
  `require_encryption` setting;
- loopback RPC default, explicit opt-in for privileged methods, and optional
  bearer-token authentication (`--rpc-token` or `rpc.token`);
- bounded HTTP/JSON parsing and client/idle timeouts.

## Verification snapshot

Executed on Windows/MSVC from this source tree:

- `cmake --workflow --preset ci`: strict warnings-as-errors MSVC build,
  ABI-manifest check and 28/28 CTest entries passed (2026-09-02);
- `scripts\\consensus-smoke.ps1 -Preset ci`: passed the 3/4 and 2/4 quorum
  cases, including pending-transaction retention below quorum;
- `scripts\\smoke.ps1 -Preset ci`: **17/17 assertions passed**. Covers
  keygen, genesis, peering, transfer, block propagation, height agreement,
  genesis binding, validator restart from finalized storage, finality record
  truncation, finalised state survival, Trocto contract compilation, contract
  deployment, counter read/write, validator disconnect observation, quorum loss
  detection and mempool rollback;
- `cmake --workflow --preset asan` was not runnable locally because this Windows
  environment has no Clang C/C++ compiler. ASan/UBSan, GCC/Clang, libsodium and
  fuzz jobs remain configured in `.github/workflows/ci.yml` and require CI or a
  matching toolchain to verify.

## Open boundaries and risks

### 1. ~~Current restart/recovery regression~~ RESOLVED

The two-node smoke scenario now passes all 17 assertions. Three root causes
were identified and fixed: (a) `system_storage_get` in `state.c` now accepts
NULL arenas for read-only borrows; (b) the fallback validator path in
`helpers.c` sorts validators by pubkey to match the genesis path; (c) the
committee is re-selected after each finalization in `consensus.c` so both
nodes converge to the same committee. A fourth fix in `event_loop.c` handles
proposal replacement when a competing block arrives from the rightful
proposer. A fifth fix in `rpc.c` relays transactions via P2P after RPC
submission.

### 2. Cryptographic deployment boundary

The default dependency-free backend is deliberately insecure: its signatures
are forgeable. The optional libsodium build provides real Ed25519 signatures and
reports `al_crypto_is_secure() == AL_TRUE` for the current controlled-validator
path. VRF and VDF functions have been removed from the codebase; only
ABI-compatible type stubs remain in `crypto.h` for struct layout stability.
The daemon gates the default backend behind `allow_insecure_crypto` in the
TOML config file or `--allow-insecure-crypto` on the CLI.

### 3. Evidence and slashing — addressed

Evidence can be encoded, gossiped, submitted through the unsafe RPC and stored
in system state. `al_evidence_verify` checks structure, conflict and committee
membership. Signature verification against reconstructed vote messages is
implemented, and evidence penalties are re-applied on restart via a durable
replay pass in the transaction execution layer. Transaction execution stores
the evidence record; the daemon's in-memory processing path applies the
penalty and the durable path replays it on restart. Unit-level evidence tests
cover creation, verification, codec roundtrip, slashing and permanent ban.
End-to-end daemon-level evidence tests exercise the full tx execution path
including durable penalty persistence across restart.

### 4. Validator-set governance — addressed

Registration and activation are implemented. The native operation enum's
governance operations (attest, challenge, challenge_response, bond_deposit,
bond_withdraw, seed_commit, seed_reveal, committee_vote) are wired into the
transaction execution layer with on-chain state persistence. Committee vote
is also handled in the daemon's consensus path. There is no finalized on-chain
governance policy for admission, withdrawal, rotation, observation authority
or dispute resolution — this remains an intentional design boundary.

### 5. PoTB remains a research model

The scoring formulas and anti-domination metrics are implemented and tested, but
there is no formal proof that a validator or correlation group cannot dominate.
COD/NDM rely on observable heuristics; ASN data and correlation-group selection
are not independently trusted oracle inputs. A patient, well-funded operator can
spread identities, infrastructure and activity to reduce detected correlation.
Parameter calibration and attack simulation on realistic validator
distributions are still required.

### 6. Transport and service exposure

P2P encryption is optional and its ephemeral key exchange is not a substitute
for an authenticated peer identity or a PKI. Peer discovery, admission policy,
rate limiting and network-level DoS controls remain deployment responsibilities.
RPC has no built-in TLS. Non-loopback read-only RPC must sit behind an
authenticated reverse proxy and network policy; privileged methods should stay
loopback-only.

### 7. Chain and operations model

The runtime accepts a single next parent and has no durable competing-branch
database, fork choice, automatic reorganisation or canonical rewind. Snapshot
import/export and pruning exist, but backup retention, restore drills,
compaction policy and production monitoring still need operational validation.
Block interval, resource prices, storage limits and committee parameters are
development defaults until benchmarked on minimum validator hardware.

## Readiness boundary

| Use | Status |
|---|---|
| Portfolio/source review | Ready |
| Local development and deterministic experiments | Ready |
| Controlled validator network | Conditional: use the documented crypto/network controls |
| Public permissionless validator admission | Not implemented |
| Untrusted public RPC or P2P exposure | Not ready without external authentication, TLS and network controls |
| Material-value public network | Not ready: requires production crypto policy, consensus/security review, PoTB research and operations tooling |

## Release gate

Before calling the implementation release-ready, require at minimum:

1. ~~A green `smoke.ps1` run including restart, contract propagation and quorum
   loss; repeat it after a clean rebuild.~~ **Done.** 17/17 assertions pass.
2. A reproducible sodium/Ed25519 build and an explicit decision on whether
   VRF/VDF are part of the intended deployment.
   **Decision: VRF/VDF are removed from the implementation and are not used in
   consensus. The sodium backend provides real Ed25519 signatures only.**
3. Signature verification and durable replay of submitted evidence/slashing,
   plus end-to-end tests for validator registration and removal/rotation.
   **Signature verification added. Durable replay added. E2E daemon-level
   evidence tests added (`test_evidence_e2e`).**
4. CI runs for strict GCC/Clang/MSVC, ASan/UBSan, fuzz smoke and determinism
   comparison on the exact release revision.
5. External review of PoTB assumptions, fork/partition behavior, key custody,
   peer authentication and production recovery procedures.

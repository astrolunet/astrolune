# Astrolune implementation audit

Audit date: 2026-08-27

## Scope and conclusion

Astrolune is ready to be shown and operated as a controlled PoTB validator
network. The repository contains a complete executable path from genesis and
transactions through deterministic execution, signed consensus, durable
finality, restart recovery and peer catch-up. Strict builds, sanitizer builds,
unit/integration tests and multi-process quorum scenarios are automated.

This conclusion is deliberately narrower than permissionless public deployment
or operation with material value. The remaining boundaries are listed below and
are documentation constraints, not hidden runtime modes.

## Current validator path

- Validator public keys form a deterministic committee shared by every node.
- The round proposer signs a block commitment bound to chain, parent, committee,
  height and round.
- Committee members sign PREVOTE and PRECOMMIT messages; unique signatures at
  the two-thirds threshold produce a finality certificate.
- Candidate blocks execute in an isolated checkpoint. Canonical state, head and
  mempool remain unchanged until a certificate is verified.
- A finalized block is executed again, then its certificate, state and block are
  synchronously committed. Commit failure stops the daemon for recovery.
- `finality.log` and `chain.log` must contain the same contiguous heights.
  Checksums, genesis binding and parent links are verified on every open.
- `signing.log` is synced before each local proposal or vote signature. It
  rejects a different signing digest for the same height, round and phase after
  either a live retry or a process restart.
- Finalized block/certificate envelopes are gossiped and served through paged
  range sync. Full 128-entry pages automatically request the next range.
- Round timeouts rotate the deterministic proposer. Losing quorum clears the
  candidate while preserving canonical state and pending transactions.

## Security and recovery controls

- RPC defaults to loopback. Key-using `transfer` and process-control `stop` are
  registered only with explicit `--unsafe-rpc`, which itself requires loopback.
- P2P frames are size bounded, peer and outbox counts are bounded, handshakes
  and idle connections expire, foreign genesis peers are rejected, and mutual
  bootstrap connections are deduplicated.
- A data directory is locked against concurrent writers and permanently bound
  to its genesis hash.
- State, block, finality and signing records are checksummed. Incomplete tail
  writes are truncated; corruption of a complete record fails closed.
- The daemon refuses a backend for which `al_crypto_is_secure()` is false unless
  the operator explicitly overrides the gate.

## Verification snapshot

The following passed on Windows/MSVC from the current source tree:

- `scripts\build.bat ci test`: strict warnings-as-errors build, 24/24 CTest
  entries;
- `scripts\build.bat asan test` with
  `ASAN_OPTIONS=allocator_may_return_null=1`: 24/24 under AddressSanitizer;
- `scripts\smoke.ps1 -Preset ci`: two validators, transaction and contract
  execution, restart recovery, torn-finality recovery and loss of quorum;
- `scripts\consensus-smoke.ps1 -Preset ci`: three of four configured validators
  finalize with one offline; two of four do not finalize and retain the pending
  transaction.

GitHub Actions also defines strict GCC, Clang and MSVC jobs, Linux ASan/UBSan,
Windows ASan, a libsodium Ed25519 build, decoder fuzz smoke runs and a
cross-toolchain determinism digest comparison.

## Remaining protocol boundaries

### PoTB model

PoTB scoring, committee selection, seed mechanics and reward arithmetic are
implemented, but their anti-domination properties are not formally proven.
Correlation-group discovery, trusted ASN observations, the proposed
network-relative weight cap and genesis-dilution policy remain open research.

The running validator set is configured identically on each node. Native PoTB
transaction schemas are consensus-encoded and stored, but registration,
evidence adjudication, slashing and committee rotation are not yet derived from
on-chain state. Changing the validator set therefore requires a coordinated
network configuration change.

### Cryptography and keys

The dependency-free signature backend and current VRF/VDF primitives are not
suitable for an adversarial public network. The optional libsodium backend uses
Ed25519, but the global secure gate remains false until VRF/VDF are replaced or
removed from protocol claims.

The proposer seed is stored in the node directory. There is no HSM/OS-keystore
adapter, remote signer, encrypted-at-rest key format or automated key rotation.
Operators must protect data-directory access and backups.

### Forks and partitions

The runtime is a linear finalized-chain protocol. It accepts the next parent or
stops; it has no competing-branch database, fork choice, reorganisation or
durable rewind. A node that misses finalized blocks catches up from peers. A
conflicting finalized history is treated as a consensus/storage violation, not
resolved automatically.

Round changes provide liveness when a proposer is absent. Byzantine partition
behavior beyond the tested quorum boundaries has not received an independent
consensus review.

### Network and operations

P2P transport is plain TCP. Proposal/vote signatures and genesis binding protect
consensus objects, but transport encryption, peer admission, discovery and
network-level denial-of-service controls are deployment responsibilities.

JSON-RPC has no authentication or TLS. Non-loopback read-only RPC exposure must
be protected by an authenticated reverse proxy and network policy; privileged
methods remain loopback-only.

Storage is append-only and crash recoverable, but has no pruning, compaction,
snapshot import/export, online backup protocol or disk-space reservation.
Resource prices, limits, block interval and timeout values require calibration
for the actual validator hardware and network.

`protocol_day` is carried and validated as part of block execution but the
running daemon does not yet advance it from an agreed wall-clock/epoch rule.

## Readiness boundary

| Use | Status |
|---|---|
| Portfolio source repository | Ready |
| Controlled validator network with known operators | Ready with the documented operational controls |
| Contract and consensus experimentation | Ready |
| Permissionless public validator admission | Not implemented |
| Untrusted public RPC or P2P exposure | Requires external network controls and further hardening |
| Material-value public network | Requires protocol proof/review, production VRF policy, hardened key custody and operational tooling |

## Resolved findings from the initial audit

The hardening work closed the original strict-build failures, unsafe default RPC
bind, remotely reachable peer-removal lifetime bug, partial-request RPC slot
exhaustion, non-paged catch-up, incorrect block-hash lookup, storage
continue-after-failure behavior, missing signed finality, speculative pending
state exposure and validator double-signing across restart. Repository licensing,
contributor guidance, security policy, ignore rules and multi-toolchain CI are
present in the current tree.

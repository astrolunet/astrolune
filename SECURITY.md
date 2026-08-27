# Security Policy

Astrolune is a controlled-network blockchain implementation. Signed validator
consensus, durable finality and restart recovery are implemented, but the PoTB
model has not received an independent protocol or cryptographic audit. The
default cryptographic backend is intentionally gated; see `AUDIT.md` for the
supported operating boundary and remaining assumptions.

## Reporting a vulnerability

Please do not open a public issue for an undisclosed security vulnerability.
Use the repository's private security advisory flow, or contact the
maintainers privately before publication. Include the commit, platform,
reproduction steps, impact and any relevant logs or sanitiser output.

There is currently no bug bounty or guaranteed response-time commitment. Once a
report is understood, we will coordinate a fix and disclosure timeline with the
reporter.

## Deployment boundary

Operate validators only inside a controlled network with known operators.
JSON-RPC has no built-in authentication or TLS. Privileged methods require an
explicit flag and a loopback bind; any wider read-only exposure needs an
authenticated reverse proxy and network policy. Do not use the default crypto
backend for adversarial or material-value operation.

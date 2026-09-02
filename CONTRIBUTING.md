# Contributing

Astrolune is a research project. Small, focused changes are easiest to review.
Please describe the invariant or user-facing behavior being changed, and call
out any protocol or wire-format compatibility impact.

## Proposing work

Search existing [issues](https://github.com/astrolunet/astrolune/issues) before
opening a new one. Use the issue forms for bug reports and feature proposals;
include a minimal reproducer, platform/toolchain details and relevant logs.
Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not a public
issue.

Pull requests should explain the motivation, list the verification commands that
were run and call out any consensus, storage, ABI or wire-format change. Keep
unrelated formatting and generated files out of the patch.

## Build and test

Use an out-of-tree CMake preset:

```powershell
cmake --preset dev
cmake --build --preset dev
ctest --preset dev --output-on-failure
```

For changes touching networking, storage, parsers or unsafe C code, also run
the `asan` preset when the local toolchain supports it. Do not commit files
under `build/`, node data directories, generated keys or logs.

Keep public headers C and C++ compatible and preserve deterministic encoding.

By contributing, you agree that your work is provided under the repository
license and that project discussions follow the [Code of Conduct](CODE_OF_CONDUCT.md).

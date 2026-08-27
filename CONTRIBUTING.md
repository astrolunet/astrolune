# Contributing

Astrolune is a research project. Small, focused changes are easiest to review.
Please describe the invariant or user-facing behavior being changed, and call
out any protocol or wire-format compatibility impact.

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

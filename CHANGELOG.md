# Changelog

## 1.0.1 — 2026-11-12

Changes since 1.0.0:

### Build and CI

- Added a GitHub Actions workflow for Linux i386 builds on Ubuntu 24.04, triggered
  by pushes to `main`/`master`, tags, pull requests, and manual dispatch.
- Pinned CI's SourceMod and SafetyHook dependencies to the locally validated
  revisions. CI runs regression tests, checks the ELF architecture and exported
  SourceMod entry point, verifies the autoload marker and config, and uploads the
  installable package.
- Removed debug information and stripped the extension binary by default. Added
  `build.py --debug` to retain debug symbols and leave the extension unstripped.
  Both modes retain `-O2` optimization.
- Documented the default build behavior and `--debug` option in the README.

### Defensive hardening

- Added an explicit null-trampoline check before enabling the loader detour.
  Initialization fails and the disabled hook is reset if the trampoline is null.
- Added checked address addition for relocated ELF segment starts and ends and
  ELF note addresses, rejecting ranges that wrap around the address space.
- Reset the parser's directory-section flag at the start of every parse.
- Limited stored denylist data to 16,384 unique enabled entries and 8 MiB of
  normalized path text across both sections. Duplicate enabled paths and disabled
  entries do not consume additional storage budget. Exceeding either limit
  rejects the config before the hook is installed.
- Documented the configuration limits and their failure behavior in the README.

### Tests

- Added regression coverage for parser reuse after successful and failed parses,
  combined entry limits, path-byte limits, duplicates and disabled entries at
  capacity, and storage-budget reset between parses.
- Added address-arithmetic tests for overflow, segment boundaries, and invalid
  ELF note addresses.
- Added integration tests using SourceMod's SMC parser for configs at and above
  the entry limit and successful parsing after a limit failure.
- Updated the extension API version check to expect 1.0.1.

The supported SourceMod logic binary and autoload-only filtering scope remain
unchanged. Live-server startup and map changes remain untested.

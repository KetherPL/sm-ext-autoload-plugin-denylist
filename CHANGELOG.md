# Changelog

## 2.0.1 — 2026-11-12

- Refactored extension initialization with Extract Method for config loading,
  path-reader checks, target discovery, and hook installation. Consolidated
  repeated hook cleanup in one method while preserving initialization order
  and the logic module handle's lifetime.
- Refactored ELF reading with Extract Method for header validation, file/module
  identity checks, function-symbol parsing, and executable-range resolution.
- Refactored scanner validation with Extract Method for result-slot validation,
  instruction decoding, unique loader-call discovery, and shared branch-entry
  checks.
- Preserved filtering behavior, configuration, validation policy, diagnostics,
  public interfaces, and the per-plugin filtering path. Pre/post-refactor
  characterization matched 2,863 scanner cases and 879 ELF cases, including exact
  diagnostic text. Regression tests passedagainst i386 SourceMod 1.12 builds 7028, 7230, and 7260.

## 2.0.0 — 2026-11-12

- Copy scan candidates into an owned, bounded buffer with Linux
  `process_vm_readv` before matching or logging. Unreadable and unterminated
  candidates are skipped safely; startup rejects an unavailable or blocked
  reader. Added page-boundary, inaccessible-memory, length-limit, and executable
  invalid-path-register regression tests.
- Replaced the build-specific internal-loader detour with a mid-function hook at
  the automatically discovered directory-scan call. Compatible updates no longer
  require a new compiled build ID, loader entry signature, or scan offset.
- Added bounded ELF symbol reading and file/loaded-image identity checks, full
  instruction decoding, unique-call validation, argument-layout checks, and
  validation that denied loads resume directory iteration.
- Preserve SourceMod's original arguments for allowed loads, including both
  observed three- and four-argument forms. Manual and dependency loads continue
  to bypass the automatic-scan filter.
- Added executable filtering and rejection fixtures and real-binary discovery and
  hook-restoration tests for i386 SourceMod 1.12.0.7028, 1.12.0.7230, and 1.12.0.7260.
  The archived x64 binary remains unsupported and is tested for rejection.
- Made `build.py --logic` repeatable and removed external symbol-offset arguments
  from the binary tests. Updated compatibility and validation documentation.

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

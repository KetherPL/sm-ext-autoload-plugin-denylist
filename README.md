# Autoload Plugin Denylist

SourceMod 1.12 extension for Linux i386. Prevents selected `.smx` files and directory
trees from loading during SourceMod's recursive automatic plugin scan. Manual
`sm plugins load` and reload operations are unaffected. Files remain in place.

## Build

Requires Python 3, GCC/G++ with 32-bit C/C++ development libraries, and a complete
SourceMod checkout containing its SourcePawn, AMTL, SafetyHook, and Zydis dependencies.
No game SDK or Metamod checkout is required. The provided checkout builds with C++17.

```sh
python3 build.py --sourcemod /kesz/Budowanie/alliedmodders/sourcemod --test \
  --logic /home/starterx4/Pulpit/gity/Kether.pl-L4D2-Server/addons/sourcemod/bin/sourcemod.logic.so
```

Output: `build/package/addons/sourcemod/`. `--logic` is optional, repeatable, and
used only with `--test`. It loads the specified binary into a standalone test process and verifies
the target, installs a temporary detour, and verifies restoration. It does not
connect to or modify a running server or change the input binary on disk.

The default build omits debug information and strips the extension binary. Pass
`--debug` to include debug symbols and keep the binary unstripped. Both modes use
the same `-O2` optimization level.

`CC` and `CXX` select compilers. `--output` selects the build directory. Rebuilding
overwrites the sample config in the output package; maintain deployment edits in
the server's config. The locally built extension requires 32-bit glibc 2.38 or
newer and libstdc++ providing `CXXABI_1.3.15` and `GLIBCXX_3.4.29`; build on the
deployment system or a compatible toolchain when distributing elsewhere.

## Install

Copy these files from the package to your server, preserving paths:

- `addons/sourcemod/extensions/autoload_plugin_denylist.ext.so`
- `addons/sourcemod/extensions/autoload_plugin_denylist.autoload` (empty marker)
- `addons/sourcemod/configs/autoload_plugin_denylist.cfg`

Edit the config, then restart the server. The `.autoload` marker loads the
extension before the plugin scan. Late extension loading is rejected because it
cannot undo plugins that have already loaded. The extension reads its config
once at initialization; restart the server after changing it.

## Config

This is SourceMod SMC/KeyValues-style configuration with two independent sections,
not INI. Paths are relative to `addons/sourcemod/plugins` and case-sensitive.
The shipped config has no active entries.

```text
"AutoloadPluginDenylist"
{
	"Plugins"
	{
		"myfork/plugin.smx" "1"
		"another_plugin.smx" "1"
	}
	"Directories"
	{
		"legacy" "1"
		"experiments/old" "1"
	}
}
```

`"1"` enables a deny entry; `"0"` leaves it inactive. A disabled entry does not
override another enabled entry or a blocked parent directory. A `Plugins` entry
matches exactly one relative path; it must include `.smx`. A `Directories` entry
matches every scanned plugin below it at any depth: `legacy` blocks
`legacy/a.smx` and `legacy/sub/b.smx`, but allows `legacy_extra/a.smx`.

Forward slashes are recommended. Backslashes, repeated separators, and `.` path
components normalize to forward-slash paths. Absolute paths, drive prefixes,
`..` components, wildcards, control characters, and empty/root paths are rejected.
Unknown, repeated, or nested sections and values other than `0`/`1` are errors.
Duplicate enabled paths collapse into one entry. Either list may be omitted or
empty. The outer `AutoloadPluginDenylist` section is required.

Across both lists, at most 16,384 unique enabled entries and 8 MiB of normalized
path text may be stored. Duplicate enabled paths and disabled entries do not
consume additional storage budget. Exceeding either limit is a config error and
prevents the extension from loading; no partial denylist is activated.

Every skipped plugin is logged through SourceMod. SourceMod's existing `disabled`
and `optional` directory rules continue to apply. Directory entries filter files
found in those trees; they do not prevent filesystem traversal or resolve symlinks
to canonical disk locations. Dependencies and explicit plugin loads can still
load a denied filename because they do not originate at the automatic scan call.
This is a startup selection tool, not a security boundary for untrusted plugins.

## Runtime compatibility and hook

The extension discovers its hook location at startup. It has no per-build address
map, fixed scan offset, loader prologue signature, or build-ID allowlist. Compatible
SourceMod updates can work with the same extension binary.

The Linux i386 logic binaries tested are 1.12.0.7028, 1.12.0.7230, and 1.12.0.7260.
Their scan call offsets differ, and the older builds supply an extra argument that
7260 omits. All three inline `CPluginManager::LoadAutoPlugin` into the directory
scanner, so hooking the standalone `LoadAutoPlugin` symbol would miss the scan.

At initialization, the extension:

1. Reads the already loaded logic module's ELF symbol table to obtain bounded
   function ranges for `LoadPluginsFromDir` and its internal `LoadPlugin` target.
2. Checks the ELF architecture, metadata bounds, executable ranges, program headers,
   and GNU build ID. The file and loaded image must match; the build ID establishes
   their identity rather than restricting which SourceMod release is accepted.
3. Decodes the scanner with Zydis and requires exactly one direct loader call on
   instruction boundaries, with no branch entering the middle of that call.
4. Validates a frame-based cdecl push sequence whose first arguments are the plugin
   manager, a zero-initialized result slot, and plugin path. Both observed three-
   and four-argument forms are recognized.
5. Checks the result-handling instructions to establish that `LoadRes_NeverLoad`
   (3) skips plugin processing and resumes the directory's `NextEntry` iteration.
6. Installs a SafetyHook mid-function hook over exactly that five-byte call.

Allowed loads execute the original call with its arguments and registers intact.
Denied loads skip that call and resume immediately afterward with result 3, allowing
SourceMod to clean up its argument stack and continue scanning. The internal loader
itself is unchanged, so explicit and dependency loads remain available. Unloading
this extension restores the original call instruction.

This remains a conservative machine-code validator, not a guarantee for arbitrary
future compilers or SourceMod internals. Unrecognized stack layouts, result dispatch,
missing/stripped symbols, ambiguous calls, file/image mismatch, malformed config,
or hook errors prevent the extension from loading. Windows and x86-64 remain
unsupported. The archived x64 binary is tested only for architecture rejection.

If discovery rejects a future update, inspect that build before expanding the
validator. Do not bypass the checks. Update SourceMod while the server is stopped;
restart after replacing its binaries so the loaded code and file agree.

SourceMod itself can continue loading plugins if this extension fails. Check the
extension status and SourceMod error logs after startup; a failed extension means
the filter is inactive.

## Validation

`--test` checks path normalization, directory matching, config limits and parser
reuse, actual SourceMod SMC parsing, checked address arithmetic, and bounded GNU
build-ID parsing. Executable i386 fixtures check runtime call discovery, rejection
of altered arguments and result handling, both observed argument counts, unchanged
allowed-call context, automatic filtering, manual-load isolation, and restoration.

Use repeated `--logic /path/to/sourcemod.logic.so` arguments with `--test` to check
multiple binaries in separate standalone processes. These tests use the same ELF
reader and instruction validator as the extension; no external symbol-offset
arguments or `nm`-generated maps are needed. They also check malformed metadata,
file/image mismatch, discovery rejection while a hook is installed, full scanner
restoration, and the built extension's API. A supplied x64 binary is expected to
be rejected by the i386 process.

Real-binary tests install and restore hooks without executing SourceMod's plugin
scan. Live-server startup and map changes remain untested.

Source references: [SourceMod plugin loading](https://github.com/alliedmodders/sourcemod/blob/master/core/logic/PluginSys.cpp)
and [extension-before-plugin startup order](https://github.com/alliedmodders/sourcemod/blob/master/core/sourcemod.cpp).
The validator recognizes the observed i386 call and result-handling layouts.

## License

Extension sources: GPL-3.0-or-later; see `LICENSE`. The build links the SourceMod
SDK wrapper (GPLv3 with AlliedModders' linking exception), SafetyHook (Boost
Software License 1.0), Zydis/Zycore (MIT), and tl::expected (CC0). Their source
notices remain in the external SourceMod checkout. See `THIRD_PARTY_NOTICES.md`.

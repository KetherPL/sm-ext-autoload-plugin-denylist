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

Output: `build/package/addons/sourcemod/`. `--logic` is optional and used only with
`--test`. It loads the specified binary into a standalone test process and verifies
the target, installs a temporary detour, and verifies restoration. It does not
connect to or modify a running server or change the input binary on disk.

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

Every skipped plugin is logged through SourceMod. SourceMod's existing `disabled`
and `optional` directory rules continue to apply. Directory entries filter files
found in those trees; they do not prevent filesystem traversal or resolve symlinks
to canonical disk locations. Dependencies and explicit plugin loads can still
load a denied filename because they do not originate at the automatic scan call.
This is a startup selection tool, not a security boundary for untrusted plugins.

## Verified binary and hook

Supported `sourcemod.logic.so` GNU build ID:

```text
a1542916a00679cbc72a6c25b5860c8d0a69c3d2
```

The supplied optimized binary inlines `CPluginManager::LoadAutoPlugin` into
`LoadPluginsFromDir`; the standalone `LoadAutoPlugin` symbol has no scan caller.
A detour on that symbol would therefore miss automatic loads.

Instead, this extension detours the internal `LoadPlugin` function and filters
only calls whose return address is the verified automatic scan call site.
The original loader handles every other call unchanged. This build removes the
unused `debug` and `type` arguments internally: the verified call ABI is
`int(void *manager, void **result, const char *path)`. A denied call returns
`LoadRes_NeverLoad` (3), which the scanner skips without creating a plugin or
calling `AddPlugin`.

Runtime validation requires the exact loaded module build ID, both internal
symbols, readable/executable address ranges, expected loader entry bytes, the
scanner's argument setup bytes, and a direct call to that loader at scanner
offset `0x416` (return offset `0x41b`). SafetyHook from the SourceMod checkout
creates/restores the trampoline. Unloading the extension removes the hook.

An unsupported or stripped binary, changed code, missing/malformed config, or
hook error prevents this extension from loading. SourceMod itself can continue
loading plugins without filtering: inspect extension status and SourceMod error
logs after startup. Do not assume exclusions took effect when the extension
failed to load.

Other SourceMod builds, Windows, and x86-64 are unsupported. Updating the target
requires fresh disassembly and ABI/call-site validation, followed by updating
`src/verified_target.h` and rerunning the binary tests. Changing only the build ID
does not establish compatibility.

## Validation

`--test` checks path normalization, exact matches, recursive directory boundaries,
case sensitivity, disabled entries, invalid config events, real SourceMod SMC
parsing, malformed ELF notes, mismatched binary rejection, and an executable
i386 fixture that distinguishes automatic and manual callers and verifies hook
restoration. `--logic` additionally validates the supplied real logic binary and
its hook installation/restoration. Live-server startup and map changes have not
been tested.

Source references: [SourceMod plugin loading](https://github.com/alliedmodders/sourcemod/blob/master/core/logic/PluginSys.cpp)
and [extension-before-plugin startup order](https://github.com/alliedmodders/sourcemod/blob/master/core/sourcemod.cpp).
The local source and supplied binary determine this extension's supported ABI.

## License

Extension sources: GPL-3.0-or-later; see `LICENSE`. The build links the SourceMod
SDK wrapper (GPLv3 with AlliedModders' linking exception), SafetyHook (Boost
Software License 1.0), Zydis/Zycore (MIT), and tl::expected (CC0). Their source
notices remain in the external SourceMod checkout. See `THIRD_PARTY_NOTICES.md`.

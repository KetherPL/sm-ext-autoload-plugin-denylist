// SPDX-License-Identifier: GPL-3.0-or-later
#include <smsdk_ext.h>
#include <safetyhook/inline_hook.hpp>
#include <cassert>
#include <cstdio>
#include <dlfcn.h>
#include <exception>
#include "denylist.h"
#include "verified_target.h"

#if !defined(__linux__) || !defined(__i386__)
#error This verified hook supports Linux i386 only.
#endif

namespace
{
// This exact optimized build passes only these three arguments. The unused
// debug/type arguments in the source declaration were removed by the compiler.
using InternalLoadPlugin = int (*)(void *manager, void **result, const char *plugin);
AutoloadDenylist::Denylist denylist;
safetyhook::InlineHook hook;
InternalLoadPlugin original_load_plugin = nullptr;
void *scan_return_address = nullptr;

__attribute__((noinline)) int FilterPluginLoad(void *manager, void **result, const char *plugin)
{
	assert(original_load_plugin);
	if (__builtin_extract_return_addr(__builtin_return_address(0)) != scan_return_address)
		return original_load_plugin(manager, result, plugin);
	try
	{
		if (denylist.Blocks(plugin))
		{
			smutils->LogMessage(myself, "Skipped automatic plugin load: %s", plugin);
			if (result)
				*result = nullptr;
			return AutoloadDenylist::kLoadNeverLoad;
		}
	}
	catch (const std::exception &exception)
	{
		// Do not leak C++ exceptions into SourceMod's plugin manager.
		// Preserve exclusion on a failed matching operation.
		smutils->LogError(myself, "Skipped automatic load after matching error: %s", exception.what());
		if (result)
			*result = nullptr;
		return AutoloadDenylist::kLoadNeverLoad;
	}
	return original_load_plugin(manager, result, plugin);
}

class AutoloadPluginDenylist final : public SDKExtension
{
public:
	bool SDK_OnLoad(char *error, size_t maxlength, bool late) override
	{
		if (late)
		{
			std::snprintf(error, maxlength, "Load at startup using autoload_plugin_denylist.autoload; late loading is unsupported");
			return false;
		}
		try
		{
			return Load(error, maxlength);
		}
		catch (const std::exception &exception)
		{
			std::snprintf(error, maxlength, "Initialization failed: %s", exception.what());
			return false;
		}
	}

	void SDK_OnUnload() override
	{
		hook.reset();
		original_load_plugin = nullptr;
		scan_return_address = nullptr;
	}

private:
	bool Load(char *error, size_t maxlength)
	{
		char config_path[PLATFORM_MAX_PATH];
		smutils->BuildPath(Path_SM, config_path, sizeof(config_path), "configs/autoload_plugin_denylist.cfg");
		SourceMod::SMCStates states{};
		const auto parse_result = textparsers->ParseFile_SMC(config_path, &denylist, &states);
		if (parse_result != SourceMod::SMCError_Okay || !denylist.IsComplete())
		{
			const char *message = denylist.Error().empty()
				? textparsers->GetSMCErrorString(parse_result) : denylist.Error().c_str();
			std::snprintf(error, maxlength, "Config error at %u:%u: %s", states.line, states.col,
				message ? message : "Missing or incomplete AutoloadPluginDenylist section");
			return false;
		}

		char logic_path[PLATFORM_MAX_PATH];
		smutils->BuildPath(Path_SM, logic_path, sizeof(logic_path), "bin/sourcemod.logic.so");
		void *module = dlopen(logic_path, RTLD_NOW | RTLD_NOLOAD);
		if (!module)
		{
			std::snprintf(error, maxlength, "Cannot access already loaded sourcemod.logic.so: %s", dlerror());
			return false;
		}
		void *target = memutils->ResolveSymbol(module, AutoloadDenylist::kTargetSymbol);
		void *scanner = memutils->ResolveSymbol(module, AutoloadDenylist::kScannerSymbol);
		dlclose(module);
		AutoloadDenylist::TargetCheck check{target, scanner};
		if (target)
			dl_iterate_phdr(AutoloadDenylist::CheckLoadedTarget, &check);
		if (!check.verified)
		{
			std::snprintf(error, maxlength, "Unsupported SourceMod logic binary, missing symbols, or modified loader/scan call site; no hook installed");
			return false;
		}

		auto created = safetyhook::InlineHook::create(target, reinterpret_cast<void *>(&FilterPluginLoad),
			safetyhook::InlineHook::Flags::StartDisabled);
		if (!created)
		{
			std::snprintf(error, maxlength, "Cannot create LoadPlugin detour (SafetyHook error %u)",
				static_cast<unsigned int>(created.error().type));
			return false;
		}
		hook = std::move(created.value());
		original_load_plugin = hook.original<InternalLoadPlugin>();
		if (!original_load_plugin)
		{
			hook.reset();
			scan_return_address = nullptr;
			std::snprintf(error, maxlength, "Cannot enable LoadPlugin detour: trampoline is null");
			return false;
		}
		scan_return_address = check.scan_return_address;
		const auto enabled = hook.enable();
		if (!enabled)
		{
			hook.reset();
			original_load_plugin = nullptr;
			scan_return_address = nullptr;
			std::snprintf(error, maxlength, "Cannot enable LoadPlugin detour (SafetyHook error %u)",
				static_cast<unsigned int>(enabled.error().type));
			return false;
		}
		smutils->LogMessage(myself, "Autoload filter enabled: %zu plugins, %zu directory trees",
			denylist.PluginCount(), denylist.DirectoryCount());
		return true;
	}
};

AutoloadPluginDenylist extension;
}

SMEXT_LINK(&extension);

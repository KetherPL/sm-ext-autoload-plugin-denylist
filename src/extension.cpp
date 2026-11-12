// SPDX-License-Identifier: GPL-3.0-or-later
#include <smsdk_ext.h>
#include <safetyhook/mid_hook.hpp>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <memory>
#include "scan_hook.h"

#if !defined(__linux__) || !defined(__i386__)
#error This verified hook supports Linux i386 only.
#endif

namespace
{
AutoloadDenylist::Denylist denylist;
safetyhook::MidHook hook;
AutoloadDenylist::TargetCheck target;

void FilterAutomaticCall(safetyhook::Context &context)
{
	assert(target.resume_address);
	try
	{
		if (AutoloadDenylist::FilterScanCall(context, denylist, target.resume_address))
			smutils->LogMessage(myself, "Skipped automatic plugin load: %s", AutoloadDenylist::ScanPluginPath(context));
	}
	catch (const std::exception &exception)
	{
		// Preserve exclusion without allowing exceptions into SourceMod's scanner.
		AutoloadDenylist::SkipScanCall(context, target.resume_address);
		smutils->LogError(myself, "Skipped automatic load after matching error: %s", exception.what());
	}
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
		target = {};
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
		auto close_module = [](void *handle) { dlclose(handle); };
		std::unique_ptr<void, decltype(close_module)> module(dlopen(logic_path, RTLD_NOW | RTLD_NOLOAD), close_module);
		if (!module)
		{
			std::snprintf(error, maxlength, "Cannot access already loaded sourcemod.logic.so: %s", dlerror());
			return false;
		}
		std::string discovery_error;
		if (!AutoloadDenylist::DiscoverTarget(module.get(), target, discovery_error))
		{
			std::snprintf(error, maxlength, "Cannot validate automatic scan: %s; no hook installed", discovery_error.c_str());
			return false;
		}

		auto created = safetyhook::MidHook::create(target.call, &FilterAutomaticCall, safetyhook::MidHook::StartDisabled);
		if (!created)
		{
			std::snprintf(error, maxlength, "Cannot create scan mid-hook (SafetyHook error %u)",
				static_cast<unsigned int>(created.error().type));
			return false;
		}
		hook = std::move(created.value());
		if (hook.original_bytes().size() != AutoloadDenylist::kRelativeCallSize ||
			std::memcmp(hook.original_bytes().data(), target.call, AutoloadDenylist::kRelativeCallSize) != 0)
		{
			hook.reset();
			target = {};
			std::snprintf(error, maxlength, "Scan mid-hook does not preserve exactly the validated call instruction");
			return false;
		}
		const auto enabled = hook.enable();
		if (!enabled)
		{
			hook.reset();
			target = {};
			std::snprintf(error, maxlength, "Cannot enable scan mid-hook (SafetyHook error %u)",
				static_cast<unsigned int>(enabled.error().type));
			return false;
		}
		smutils->LogMessage(myself, "Autoload filter enabled at discovered scan call +0x%zx: %zu plugins, %zu directory trees",
			static_cast<size_t>(target.call - target.scanner), denylist.PluginCount(), denylist.DirectoryCount());
		return true;
	}
};

AutoloadPluginDenylist extension;
}

SMEXT_LINK(&extension);

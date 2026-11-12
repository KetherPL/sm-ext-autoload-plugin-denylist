// SPDX-License-Identifier: GPL-3.0-or-later
#include "verified_target.h"
#include <IExtensionSys.h>
#include <safetyhook/inline_hook.hpp>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

int Replacement(void *, void **, const char *)
{
	return AutoloadDenylist::kLoadNeverLoad;
}

int main(int argc, char **argv)
{
	assert(argc == 5);
	void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!module)
	{
		std::fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	link_map *mapping = nullptr;
	assert(dlinfo(module, RTLD_DI_LINKMAP, &mapping) == 0 && mapping);
	const uintptr_t base = mapping->l_addr;
	AutoloadDenylist::TargetCheck check{
		reinterpret_cast<void *>(base + std::strtoul(argv[2], nullptr, 16)),
		reinterpret_cast<void *>(base + std::strtoul(argv[3], nullptr, 16))};
	dl_iterate_phdr(AutoloadDenylist::CheckLoadedTarget, &check);
	assert(check.verified && check.scan_return_address);
	auto created = safetyhook::InlineHook::create(check.address, reinterpret_cast<void *>(&Replacement),
		safetyhook::InlineHook::Flags::StartDisabled);
	assert(created);
	auto hook = std::move(created.value());
	assert(hook.enable());
	check.verified = false;
	dl_iterate_phdr(AutoloadDenylist::CheckLoadedTarget, &check);
	assert(!check.verified);
	hook.reset();
	dl_iterate_phdr(AutoloadDenylist::CheckLoadedTarget, &check);
	assert(check.verified);
	dlclose(module);
	void *extension = dlopen(argv[4], RTLD_NOW | RTLD_LOCAL);
	if (!extension)
	{
		std::fprintf(stderr, "Extension dlopen: %s\n", dlerror());
		return 1;
	}
	using GetExtensionAPI = SourceMod::IExtensionInterface *(*)();
	auto factory = reinterpret_cast<GetExtensionAPI>(dlsym(extension, "GetSMExtAPI"));
	assert(factory);
	auto *api = factory();
	assert(api && std::strcmp(api->GetExtensionVerString(), "1.0.1") == 0);
	assert(std::strcmp(api->GetExtensionName(), "Autoload Plugin Denylist") == 0);
	dlclose(extension);
	std::puts("Supplied SourceMod binary: build ID, loader ABI entry, scan call site, detour installation/restoration passed");
	std::puts("Built extension: dynamic loading and SourceMod API factory passed");
}

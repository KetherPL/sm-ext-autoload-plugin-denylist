// SPDX-License-Identifier: GPL-3.0-or-later
#include "verified_target.h"
#include <IExtensionSys.h>
#include <safetyhook/mid_hook.hpp>
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fstream>

namespace
{
void Replacement(safetyhook::Context &) {}

int Snapshot(dl_phdr_info *module, size_t, void *context)
{
	auto &requested = *static_cast<dl_phdr_info *>(context);
	if (module->dlpi_addr != requested.dlpi_addr)
		return 0;
	requested = *module;
	return 1;
}

void TestMalformedImages(const char *path, void *module)
{
	link_map *mapping = nullptr;
	assert(dlinfo(module, RTLD_DI_LINKMAP, &mapping) == 0 && mapping);
	dl_phdr_info snapshot{};
	snapshot.dlpi_addr = mapping->l_addr;
	dl_iterate_phdr(Snapshot, &snapshot);
	assert(snapshot.dlpi_phdr);
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	assert(file);
	std::vector<unsigned char> image(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	assert(file.read(reinterpret_cast<char *>(image.data()), image.size()));
	AutoloadDenylist::TargetCheck check;
	std::string error;
	assert(AutoloadDenylist::ReadTargetImage(image, snapshot, check, error));
	auto corrupted = image;
	corrupted[EI_CLASS] = ELFCLASS64;
	assert(!AutoloadDenylist::ReadTargetImage(corrupted, snapshot, check, error));
	corrupted = image;
	ElfW(Ehdr) header;
	std::memcpy(&header, image.data(), sizeof(header));
	header.e_shoff = UINT32_MAX;
	std::memcpy(corrupted.data(), &header, sizeof(header));
	assert(!AutoloadDenylist::ReadTargetImage(corrupted, snapshot, check, error));
	std::memcpy(&header, image.data(), sizeof(header));
	corrupted = image;
	header.e_shnum = 0;
	std::memcpy(corrupted.data(), &header, sizeof(header));
	assert(!AutoloadDenylist::ReadTargetImage(corrupted, snapshot, check, error));
	for (size_t index = 0; index < snapshot.dlpi_phnum; index++)
	{
		const auto &segment = snapshot.dlpi_phdr[index];
		if (segment.p_type != PT_NOTE)
			continue;
		std::vector<unsigned char> build_id;
		if (!AutoloadDenylist::ReadBuildId(image.data() + segment.p_offset, segment.p_filesz, build_id))
			continue;
		corrupted = image;
		const auto position = std::search(corrupted.begin() + segment.p_offset,
			corrupted.begin() + segment.p_offset + segment.p_filesz, build_id.begin(), build_id.end());
		assert(position != corrupted.begin() + segment.p_offset + segment.p_filesz);
		*position ^= 1;
		assert(!AutoloadDenylist::ReadTargetImage(corrupted, snapshot, check, error));
		assert(error.find("build ID differs") != std::string::npos);
		break;
	}
	assert(!AutoloadDenylist::ReadTargetImage({}, snapshot, check, error));
}
}

int main(int argc, char **argv)
{
	assert(argc == 3);
	std::ifstream input(argv[1], std::ios::binary);
	unsigned char identification[EI_NIDENT]{};
	assert(input.read(reinterpret_cast<char *>(identification), sizeof(identification)));
	void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (identification[EI_CLASS] == ELFCLASS64)
	{
		assert(!module);
		std::printf("%s: x64 binary rejected by i386 process as expected\n", argv[1]);
		return 0;
	}
	if (!module)
	{
		std::fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	AutoloadDenylist::TargetCheck check;
	std::string error;
	if (!AutoloadDenylist::DiscoverTarget(module, check, error))
	{
		std::fprintf(stderr, "Discovery failed: %s\n", error.c_str());
		return 1;
	}
	const size_t call_offset = check.call - check.scanner;
	std::vector<unsigned char> original(check.scanner, check.scanner + check.scanner_size);
	TestMalformedImages(argv[1], module);
	auto created = safetyhook::MidHook::create(check.call, &Replacement, safetyhook::MidHook::StartDisabled);
	assert(created);
	auto hook = std::move(created.value());
	assert(hook.original_bytes().size() == AutoloadDenylist::kRelativeCallSize);
	assert(hook.enable());
	assert(!AutoloadDenylist::DiscoverTarget(module, check, error));
	hook.reset();
	assert(AutoloadDenylist::DiscoverTarget(module, check, error));
	assert(std::memcmp(original.data(), check.scanner, check.scanner_size) == 0);
	dlclose(module);
	void *extension = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
	assert(extension);
	using GetExtensionAPI = SourceMod::IExtensionInterface *(*)();
	auto factory = reinterpret_cast<GetExtensionAPI>(dlsym(extension, "GetSMExtAPI"));
	assert(factory);
	auto *api = factory();
	assert(api && std::strcmp(api->GetExtensionVerString(), "2.0.0") == 0);
	assert(std::strcmp(api->GetExtensionName(), "Autoload Plugin Denylist") == 0);
	dlclose(extension);
	std::printf("%s: automatic discovery +0x%zx, ELF rejection cases, mid-hook restoration, and extension API passed\n",
		argv[1], call_offset);
}

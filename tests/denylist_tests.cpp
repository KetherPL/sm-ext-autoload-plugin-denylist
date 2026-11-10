// SPDX-License-Identifier: GPL-3.0-or-later
#include "denylist.h"
#include "verified_target.h"
#include <safetyhook/inline_hook.hpp>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace AutoloadDenylist;
using namespace SourceMod;

namespace
{
void TestPaths()
{
	std::string normalized;
	assert(NormalizePath("./folder//plugin.smx", false, normalized));
	assert(normalized == "folder/plugin.smx");
	assert(NormalizePath("folder\\nested\\plugin.smx", false, normalized));
	assert(normalized == "folder/nested/plugin.smx");
	assert(NormalizePath("folder/", true, normalized) && normalized == "folder");
	for (const char *path : {"", "/absolute.smx", "\\absolute.smx", "../a.smx",
		"folder/../a.smx", "C:/a.smx", "folder/*.smx", "what?.smx", "a.smx/",
		"plugin", "plugin.SMX", ".", "a\n.smx"})
		assert(!NormalizePath(path, false, normalized));
	assert(!NormalizePath("./", true, normalized));
	assert(!NormalizePath(nullptr, false, normalized));
	assert(!NormalizePath(std::string(kMaxRelativePath + 1, 'a').c_str(), true, normalized));
}

void TestListener()
{
	Denylist config;
	config.ReadSMC_ParseStart();
	assert(config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist") == SMCResult_Continue);
	assert(config.ReadSMC_NewSection(nullptr, "Plugins") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "./folder/plugin.smx", "1") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "folder/plugin.smx", "1") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "enabled.smx", "0") == SMCResult_Continue);
	config.ReadSMC_LeavingSection(nullptr);
	assert(config.ReadSMC_NewSection(nullptr, "Directories") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "old/", "1") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "enabled", "0") == SMCResult_Continue);
	config.ReadSMC_LeavingSection(nullptr);
	config.ReadSMC_LeavingSection(nullptr);
	config.ReadSMC_ParseEnd(false, false);
	assert(config.IsComplete());
	assert(config.PluginCount() == 1 && config.DirectoryCount() == 1);
	assert(config.Blocks("folder/plugin.smx"));
	assert(config.Blocks("folder\\plugin.smx"));
	assert(config.Blocks("old/a.smx") && config.Blocks("old/sub/nested.smx"));
	assert(!config.Blocks("older/a.smx") && !config.Blocks("sub/old/a.smx"));
	assert(!config.Blocks("old.smx") && !config.Blocks("enabled.smx"));
	assert(!config.Blocks("Folder/plugin.smx") && !config.Blocks("old/../a.smx"));
	assert(!config.Blocks("unrelated.smx"));

	config.ReadSMC_ParseStart();
	config.ReadSMC_ParseEnd(false, false);
	assert(!config.IsComplete() && config.PluginCount() == 0);
	assert(config.ReadSMC_NewSection(nullptr, "Unknown") == SMCResult_HaltFail);
	assert(!config.Error().empty());
	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	assert(config.ReadSMC_KeyValue(nullptr, "a.smx", "1") == SMCResult_HaltFail);
	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	config.ReadSMC_NewSection(nullptr, "Plugins");
	assert(config.ReadSMC_KeyValue(nullptr, "a.smx", "yes") == SMCResult_HaltFail);
	assert(config.ReadSMC_KeyValue(nullptr, "../a.smx", "1") == SMCResult_HaltFail);
	config.ReadSMC_ParseEnd(true, true);
	assert(!config.IsComplete());
	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	config.ReadSMC_NewSection(nullptr, "Plugins");
	assert(config.ReadSMC_NewSection(nullptr, "Nested") == SMCResult_HaltFail);
	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	config.ReadSMC_NewSection(nullptr, "Plugins");
	config.ReadSMC_LeavingSection(nullptr);
	assert(config.ReadSMC_NewSection(nullptr, "Plugins") == SMCResult_HaltFail);
}

void TestBinaryValidation()
{
	std::array<unsigned char, 36> notes{};
	ElfW(Nhdr) note{4, kBuildId.size(), NT_GNU_BUILD_ID};
	std::memcpy(notes.data(), &note, sizeof(note));
	std::memcpy(notes.data() + sizeof(note), "GNU\0", 4);
	std::memcpy(notes.data() + sizeof(note) + 4, kBuildId.data(), kBuildId.size());
	std::array<ElfW(Phdr), 2> segments{};
	for (auto &segment : segments)
	{
		segment.p_vaddr = reinterpret_cast<uintptr_t>(notes.data());
		segment.p_memsz = notes.size();
		segment.p_flags = PF_R;
	}
	segments[0].p_type = PT_LOAD;
	segments[1].p_type = PT_NOTE;
	dl_phdr_info module{};
	module.dlpi_phdr = segments.data();
	module.dlpi_phnum = segments.size();
	assert(HasSupportedBuildId(module));
	notes.back() ^= 1;
	assert(!HasSupportedBuildId(module));
	notes.back() ^= 1;
	segments[1].p_memsz--;
	assert(!HasSupportedBuildId(module));
	segments[1].p_memsz++;
	segments[0].p_flags = 0;
	assert(!HasSupportedBuildId(module));
	segments[0].p_flags = PF_R;
	note.n_namesz = UINT32_MAX;
	std::memcpy(notes.data(), &note, sizeof(note));
	assert(!HasSupportedBuildId(module));
	TargetCheck check{reinterpret_cast<void *>(&TestBinaryValidation)};
	dl_iterate_phdr(CheckLoadedTarget, &check);
	assert(!check.verified);
}

safetyhook::InlineHook test_hook;
int calls = 0;
void *last_manager = nullptr;
std::string last_plugin;
using InternalLoad = int (*)(void *, void **, const char *);

// Match the supplied build's initial instructions and exercise the i386 member ABI.
extern "C" int FixtureBody(void *manager, void **result, const char *plugin)
{
	calls++;
	last_manager = manager;
	last_plugin = plugin;
	*result = manager;
	return 0;
}
extern "C" int Fixture(void *, void **, const char *);
extern "C" int FixtureScanner(void *, void **, const char *);
extern "C" char FixtureScanReturn;
asm(".text\n"
	".global Fixture\n"
	".type Fixture,@function\n"
	"Fixture:\n"
	"push %ebp\n mov %esp,%ebp\n push %ebx\n push %edi\n push %esi\n"
	"push 16(%ebp)\n push 12(%ebp)\n push 8(%ebp)\n call FixtureBody\n add $12,%esp\n"
	"pop %esi\n pop %edi\n pop %ebx\n leave\n ret\n"
	".size Fixture,.-Fixture\n"
	".global FixtureScanner\n .type FixtureScanner,@function\n"
	"FixtureScanner:\n push %ebp\n mov %esp,%ebp\n sub $12,%esp\n"
	"push 16(%ebp)\n push 12(%ebp)\n push 8(%ebp)\n call Fixture\n"
	".global FixtureScanReturn\n FixtureScanReturn:\n add $12,%esp\n leave\n ret\n"
	".size FixtureScanner,.-FixtureScanner\n");

__attribute__((noinline)) int FixtureDetour(void *manager, void **result, const char *plugin)
{
	if (__builtin_extract_return_addr(__builtin_return_address(0)) == &FixtureScanReturn &&
		std::strcmp(plugin, "blocked.smx") == 0)
	{
		*result = nullptr;
		return kLoadNeverLoad;
	}
	return test_hook.original<InternalLoad>()(manager, result, plugin);
}

void TestDetour()
{
	std::array<unsigned char, kEntryBytes.size()> original;
	std::memcpy(original.data(), reinterpret_cast<void *>(&Fixture), original.size());
	auto created = safetyhook::InlineHook::create(reinterpret_cast<void *>(&Fixture),
		reinterpret_cast<void *>(&FixtureDetour), safetyhook::InlineHook::Flags::StartDisabled);
	assert(created);
	test_hook = std::move(created.value());
	assert(test_hook.enable());
	int manager = 0;
	void *result = &manager;
	assert(FixtureScanner(&manager, &result, "blocked.smx") == kLoadNeverLoad);
	assert(calls == 0 && result == nullptr);
	assert(FixtureScanner(&manager, &result, "allowed.smx") == 0);
	assert(calls == 1 && result == &manager && last_manager == &manager && last_plugin == "allowed.smx");
	assert(Fixture(&manager, &result, "blocked.smx") == 0);
	assert(calls == 2 && last_plugin == "blocked.smx");
	test_hook.reset();
	assert(std::memcmp(original.data(), reinterpret_cast<void *>(&Fixture), original.size()) == 0);
	assert(FixtureScanner(&manager, &result, "blocked.smx") == 0);
	assert(calls == 3 && last_plugin == "blocked.smx");
}
}

int main()
{
	static_assert(sizeof(void *) == 4, "The ABI regression must run as i386");
	TestPaths();
	TestListener();
	TestBinaryValidation();
	TestDetour();
	std::puts("Path, config listener, binary validation, and i386 detour tests passed");
}

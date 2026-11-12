// SPDX-License-Identifier: GPL-3.0-or-later
#include "denylist.h"
#include "verified_target.h"
#include <array>
#include <algorithm>
#include <cstring>
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

void TestParserReuse()
{
	Denylist config;
	for (bool fail_parse : {false, true})
	{
		config.ReadSMC_ParseStart();
		config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
		config.ReadSMC_NewSection(nullptr, "Directories");
		assert(config.ReadSMC_KeyValue(nullptr, "old", "1") == SMCResult_Continue);
		if (fail_parse)
		{
			assert(config.ReadSMC_NewSection(nullptr, "Invalid") == SMCResult_HaltFail);
			config.ReadSMC_ParseEnd(true, true);
		} else {
			config.ReadSMC_LeavingSection(nullptr);
			config.ReadSMC_LeavingSection(nullptr);
			config.ReadSMC_ParseEnd(false, false);
			assert(config.IsComplete());
		}
		config.ReadSMC_ParseStart();
		assert(config.Error().empty() && !config.IsComplete());
		assert(config.PluginCount() == 0 && config.DirectoryCount() == 0);
		config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
		config.ReadSMC_NewSection(nullptr, "Plugins");
		assert(config.ReadSMC_KeyValue(nullptr, "new.smx", "1") == SMCResult_Continue);
		config.ReadSMC_LeavingSection(nullptr);
		config.ReadSMC_LeavingSection(nullptr);
		config.ReadSMC_ParseEnd(false, false);
		assert(config.IsComplete() && config.Blocks("new.smx"));
		assert(!config.Blocks("new.smx/nested.smx") && !config.Blocks("old/a.smx"));
	}
}

void TestConfigLimits()
{
	Denylist config;
	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	config.ReadSMC_NewSection(nullptr, "Directories");
	for (size_t index = 0; index < kMaxDenylistEntries - 1; index++)
	{
		const std::string path = "directory" + std::to_string(index);
		assert(config.ReadSMC_KeyValue(nullptr, path.c_str(), "1") == SMCResult_Continue);
	}
	config.ReadSMC_LeavingSection(nullptr);
	config.ReadSMC_NewSection(nullptr, "Plugins");
	assert(config.ReadSMC_KeyValue(nullptr, "last.smx", "1") == SMCResult_Continue);
	assert(config.PluginCount() + config.DirectoryCount() == kMaxDenylistEntries);
	assert(config.ReadSMC_KeyValue(nullptr, "last.smx", "1") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "disabled.smx", "0") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "overflow.smx", "1") == SMCResult_HaltFail);
	assert(config.PluginCount() == 1 && config.DirectoryCount() == kMaxDenylistEntries - 1);
	assert(config.Error().find("entries") != std::string::npos);
	config.ReadSMC_ParseEnd(true, true);
	assert(!config.IsComplete());

	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	config.ReadSMC_NewSection(nullptr, "Directories");
	size_t remaining_bytes = kMaxDenylistPathBytes;
	size_t entry_index = 0;
	while (remaining_bytes >= kMaxRelativePath)
	{
		std::string path = std::to_string(entry_index++);
		path.resize(kMaxRelativePath, 'a');
		assert(config.ReadSMC_KeyValue(nullptr, path.c_str(), "1") == SMCResult_Continue);
		remaining_bytes -= path.size();
	}
	assert(remaining_bytes > 0);
	const std::string last_path(remaining_bytes, 'z');
	assert(config.ReadSMC_KeyValue(nullptr, last_path.c_str(), "1") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, last_path.c_str(), "1") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "disabled", "0") == SMCResult_Continue);
	assert(config.ReadSMC_KeyValue(nullptr, "q", "1") == SMCResult_HaltFail);
	assert(config.Error().find("storage") != std::string::npos);
	config.ReadSMC_ParseEnd(true, true);
	assert(!config.IsComplete());

	config.ReadSMC_ParseStart();
	config.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	config.ReadSMC_NewSection(nullptr, "Plugins");
	assert(config.ReadSMC_KeyValue(nullptr, "fresh.smx", "1") == SMCResult_Continue);
	config.ReadSMC_LeavingSection(nullptr);
	config.ReadSMC_LeavingSection(nullptr);
	config.ReadSMC_ParseEnd(false, false);
	assert(config.IsComplete() && config.PluginCount() == 1 && config.DirectoryCount() == 0);
}

void TestAddressArithmetic()
{
	const uintptr_t maximum_address = std::numeric_limits<uintptr_t>::max();
	uintptr_t result;
	assert(CheckedAddressAdd(0, 0, result) && result == 0);
	assert(CheckedAddressAdd(maximum_address, 0, result) && result == maximum_address);
	assert(CheckedAddressAdd(maximum_address - 1, 1, result) && result == maximum_address);
	assert(!CheckedAddressAdd(maximum_address, 1, result));

	ElfW(Phdr) segment{};
	segment.p_type = PT_LOAD;
	segment.p_vaddr = 1;
	segment.p_memsz = 1;
	segment.p_flags = PF_R | PF_X;
	dl_phdr_info module{};
	module.dlpi_addr = maximum_address;
	module.dlpi_phdr = &segment;
	module.dlpi_phnum = 1;
	assert(!InSegment(module, 0, 1, PF_R));
	module.dlpi_addr = maximum_address - 1;
	assert(!InSegment(module, maximum_address, 1, PF_R));
	module.dlpi_addr = 0;
	assert(InSegment(module, 1, 1, PF_R | PF_X));
	assert(InSegment(module, 2, 0, PF_R));
	assert(!InSegment(module, 2, 1, PF_R));
	assert(!InSegment(module, 0, 1, PF_R));
	assert(!InSegment(module, 1, maximum_address, PF_R));
	segment.p_type = PT_NOTE;
	module.dlpi_addr = maximum_address;
	assert(!InSegment(module, 0, 1, PF_R));
}

void TestBinaryValidation()
{
	std::array<unsigned char, 20> expected{};
	for (size_t index = 0; index < expected.size(); index++)
		expected[index] = static_cast<unsigned char>(index);
	std::array<unsigned char, 36> notes{};
	ElfW(Nhdr) note{4, expected.size(), NT_GNU_BUILD_ID};
	std::memcpy(notes.data(), &note, sizeof(note));
	std::memcpy(notes.data() + sizeof(note), "GNU\0", 4);
	std::memcpy(notes.data() + sizeof(note) + 4, expected.data(), expected.size());
	std::vector<unsigned char> build_id;
	assert(ReadBuildId(notes.data(), notes.size(), build_id));
	assert(std::equal(build_id.begin(), build_id.end(), expected.begin(), expected.end()));
	notes.back() ^= 1;
	assert(ReadBuildId(notes.data(), notes.size(), build_id));
	assert(build_id.back() != expected.back());
	assert(!ReadBuildId(notes.data(), notes.size() - 1, build_id));
	assert(build_id.empty());
	note.n_namesz = UINT32_MAX;
	std::memcpy(notes.data(), &note, sizeof(note));
	assert(!ReadBuildId(notes.data(), notes.size(), build_id));
	note.n_namesz = 4;
	note.n_descsz = 0;
	std::memcpy(notes.data(), &note, sizeof(note));
	assert(!ReadBuildId(notes.data(), notes.size(), build_id));
	assert(!ReadBuildId(nullptr, 0, build_id));
}

}

int main()
{
	static_assert(sizeof(void *) == 4, "The ABI regression must run as i386");
	TestPaths();
	TestListener();
	TestParserReuse();
	TestConfigLimits();
	TestAddressArithmetic();
	TestBinaryValidation();
	std::puts("Path, config, ELF note, and checked-address tests passed");
}

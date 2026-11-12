// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <link.h>
#include <limits>
#include <string>
#include <vector>

namespace AutoloadDenylist
{
inline constexpr char kTargetSymbol[] = "_ZN14CPluginManager10LoadPluginEPP7CPluginPKcbN9SourceMod10PluginTypeE";
inline constexpr char kScannerSymbol[] = "_ZN14CPluginManager18LoadPluginsFromDirEPKcS1_";
inline constexpr size_t kRelativeCallSize = 5;
inline constexpr int kLoadNeverLoad = 3;
inline constexpr size_t kMaxScannerBytes = 128 * 1024;
inline constexpr size_t kMaxLogicFileBytes = 64 * 1024 * 1024;

inline bool CheckedAddressAdd(uintptr_t base, uintptr_t offset, uintptr_t &result)
{
	if (offset > std::numeric_limits<uintptr_t>::max() - base)
		return false;
	result = base + offset;
	return true;
}

inline bool InSegment(const dl_phdr_info &module, uintptr_t address, size_t length,
	unsigned int required_flags)
{
	for (size_t index = 0; index < module.dlpi_phnum; index++)
	{
		const auto &segment = module.dlpi_phdr[index];
		if (segment.p_type != PT_LOAD || (segment.p_flags & required_flags) != required_flags)
			continue;
		uintptr_t start;
		uintptr_t end;
		if (!CheckedAddressAdd(module.dlpi_addr, segment.p_vaddr, start) ||
			!CheckedAddressAdd(start, segment.p_memsz, end))
			continue;
		if (address >= start && address <= end && length <= end - address)
			return true;
	}
	return false;
}

struct TargetCheck
{
	void *loader = nullptr;
	unsigned char *scanner = nullptr;
	size_t scanner_size = 0;
	unsigned char *call = nullptr;
	uintptr_t resume_address = 0;
};

// The ELF file must describe the same image that is already loaded in this process.
// Build IDs establish file/image identity, not a list of allowed SourceMod builds.
bool ReadBuildId(const unsigned char *notes, size_t size, std::vector<unsigned char> &build_id);
bool ReadTargetImage(const std::vector<unsigned char> &image, const dl_phdr_info &module,
	TargetCheck &target, std::string &error);
bool DiscoverTarget(void *module_handle, TargetCheck &target, std::string &error);
bool ValidateScanCode(TargetCheck &target, std::string &error);
}

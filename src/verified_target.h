// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <link.h>

namespace AutoloadDenylist
{
inline constexpr char kTargetSymbol[] = "_ZN14CPluginManager10LoadPluginEPP7CPluginPKcbN9SourceMod10PluginTypeE";
inline constexpr char kScannerSymbol[] = "_ZN14CPluginManager18LoadPluginsFromDirEPKcS1_";
inline constexpr size_t kScanCallOffset = 0x416;
inline constexpr size_t kRelativeCallSize = 5;
inline constexpr int kLoadNeverLoad = 3;
inline constexpr std::array<unsigned char, 18> kScanCallPrefix = {
	0xc7, 0x45, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x83, 0xec,
	0x14, 0x57, 0x8d, 0x45, 0xf0, 0x50, 0xff, 0x75, 0x08
};
inline constexpr std::array<unsigned char, 20> kBuildId = {
	0xa1, 0x54, 0x29, 0x16, 0xa0, 0x06, 0x79, 0xcb, 0xc7, 0x2a,
	0x6c, 0x25, 0xb5, 0x86, 0x0c, 0x8d, 0x0a, 0x69, 0xc3, 0xd2
};
inline constexpr std::array<unsigned char, 16> kEntryBytes = {
	0x55, 0x89, 0xe5, 0x53, 0x57, 0x56, 0x83, 0xec,
	0x2c, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x81
};

inline bool InSegment(const dl_phdr_info &module, uintptr_t address, size_t length,
	unsigned int required_flags)
{
	for (size_t index = 0; index < module.dlpi_phnum; index++)
	{
		const auto &segment = module.dlpi_phdr[index];
		if (segment.p_type != PT_LOAD || (segment.p_flags & required_flags) != required_flags)
			continue;
		const uintptr_t start = module.dlpi_addr + segment.p_vaddr;
		if (address >= start && address - start <= segment.p_memsz &&
			length <= segment.p_memsz - (address - start))
			return true;
	}
	return false;
}

inline bool HasSupportedBuildId(const dl_phdr_info &module)
{
	for (size_t index = 0; index < module.dlpi_phnum; index++)
	{
		const auto &segment = module.dlpi_phdr[index];
		const uintptr_t address = module.dlpi_addr + segment.p_vaddr;
		if (segment.p_type != PT_NOTE || !InSegment(module, address, segment.p_memsz, PF_R))
			continue;
		const auto *notes = reinterpret_cast<const unsigned char *>(address);
		size_t offset = 0;
		while (segment.p_memsz - offset >= sizeof(ElfW(Nhdr)))
		{
			ElfW(Nhdr) note;
			std::memcpy(&note, notes + offset, sizeof(note));
			offset += sizeof(note);
			// Bounds-check before aligning, including on 32-bit hosts.
			const size_t remaining = segment.p_memsz - offset;
			if (note.n_namesz > remaining || remaining - note.n_namesz < 3)
				break;
			const size_t name_size = (static_cast<size_t>(note.n_namesz) + 3) & ~size_t(3);
			if (name_size > remaining || note.n_descsz > remaining - name_size)
				break;
			if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
				std::memcmp(notes + offset, "GNU\0", 4) == 0 && note.n_descsz == kBuildId.size())
				return std::memcmp(notes + offset + name_size, kBuildId.data(), kBuildId.size()) == 0;
			const size_t description_remaining = remaining - name_size;
			if (description_remaining - note.n_descsz < 3)
				break;
			const size_t description_size = (static_cast<size_t>(note.n_descsz) + 3) & ~size_t(3);
			offset += name_size + description_size;
		}
	}
	return false;
}

struct TargetCheck
{
	void *address;
	void *scanner = nullptr;
	void *scan_return_address = nullptr;
	bool verified = false;
};

inline int CheckLoadedTarget(dl_phdr_info *module, size_t, void *context)
{
	auto &check = *static_cast<TargetCheck *>(context);
	if (!InSegment(*module, reinterpret_cast<uintptr_t>(check.address), kEntryBytes.size(), PF_R | PF_X))
		return 0;
	if (!HasSupportedBuildId(*module) ||
		std::memcmp(check.address, kEntryBytes.data(), kEntryBytes.size()) != 0 ||
		!InSegment(*module, reinterpret_cast<uintptr_t>(check.scanner),
			kScanCallOffset + kRelativeCallSize, PF_R | PF_X))
		return 1;
	const auto *call = static_cast<const unsigned char *>(check.scanner) + kScanCallOffset;
	if (call[0] != 0xe8 || std::memcmp(call - kScanCallPrefix.size(),
		kScanCallPrefix.data(), kScanCallPrefix.size()) != 0)
		return 1;
	uint32_t displacement;
	std::memcpy(&displacement, call + 1, sizeof(displacement));
	const uintptr_t return_address = reinterpret_cast<uintptr_t>(call + kRelativeCallSize);
	if (static_cast<uint32_t>(return_address) + displacement !=
		static_cast<uint32_t>(reinterpret_cast<uintptr_t>(check.address)))
		return 1;
	check.scan_return_address = reinterpret_cast<void *>(return_address);
	check.verified = true;
	return 1;
}
}

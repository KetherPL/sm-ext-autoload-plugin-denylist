// SPDX-License-Identifier: GPL-3.0-or-later
#include "verified_target.h"
#include <cstring>
#include <dlfcn.h>
#include <fstream>

namespace AutoloadDenylist
{
namespace
{
constexpr size_t kMaxBuildIdBytes = 64;

bool Fail(std::string &error, const char *message)
{
	error = message;
	return false;
}

bool FileRange(const std::vector<unsigned char> &image, size_t offset, size_t length)
{
	return offset <= image.size() && length <= image.size() - offset;
}

template <typename Value>
bool ReadValue(const std::vector<unsigned char> &image, size_t offset, Value &value)
{
	if (!FileRange(image, offset, sizeof(value)))
		return false;
	std::memcpy(&value, image.data() + offset, sizeof(value));
	return true;
}

struct ModuleSnapshot
{
	uintptr_t base;
	dl_phdr_info info{};
	bool found = false;
};

int FindModule(dl_phdr_info *module, size_t, void *context)
{
	auto &snapshot = *static_cast<ModuleSnapshot *>(context);
	if (module->dlpi_addr != snapshot.base)
		return 0;
	// The program-header array belongs to the loaded module, held by dlopen.
	snapshot.info = *module;
	snapshot.found = true;
	return 1;
}
}

bool ReadBuildId(const unsigned char *notes, size_t size, std::vector<unsigned char> &build_id)
{
	build_id.clear();
	size_t offset = 0;
	while (size - offset >= sizeof(ElfW(Nhdr)))
	{
		ElfW(Nhdr) note;
		std::memcpy(&note, notes + offset, sizeof(note));
		offset += sizeof(note);
		const size_t remaining = size - offset;
		if (note.n_namesz > std::numeric_limits<size_t>::max() - 3 ||
			note.n_descsz > std::numeric_limits<size_t>::max() - 3)
			return false;
		const size_t name_size = (static_cast<size_t>(note.n_namesz) + 3) & ~size_t(3);
		const size_t description_size = (static_cast<size_t>(note.n_descsz) + 3) & ~size_t(3);
		if (name_size > remaining || description_size > remaining - name_size)
			return false;
		if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
			std::memcmp(notes + offset, "GNU\0", 4) == 0)
		{
			if (!note.n_descsz || note.n_descsz > kMaxBuildIdBytes)
				return false;
			build_id.assign(notes + offset + name_size, notes + offset + name_size + note.n_descsz);
			return true;
		}
		offset += name_size + description_size;
	}
	return false;
}

namespace
{
bool ReadImageHeader(const std::vector<unsigned char> &image, const dl_phdr_info &module,
	ElfW(Ehdr) &header, std::string &error)
{
	if (image.size() > kMaxLogicFileBytes || !ReadValue(image, 0, header) ||
		std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
		header.e_ident[EI_CLASS] != ELFCLASS32 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
		header.e_ident[EI_VERSION] != EV_CURRENT || header.e_version != EV_CURRENT ||
		header.e_machine != EM_386 || header.e_type != ET_DYN ||
		header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(ElfW(Phdr)) ||
		header.e_shentsize != sizeof(ElfW(Shdr)) || !header.e_shnum || !header.e_phnum ||
		header.e_phnum != module.dlpi_phnum ||
		!FileRange(image, header.e_phoff, size_t(header.e_phnum) * sizeof(ElfW(Phdr))) ||
		!FileRange(image, header.e_shoff, size_t(header.e_shnum) * sizeof(ElfW(Shdr))))
		return Fail(error, "Invalid, unsupported, or truncated Linux i386 ELF metadata");

	return true;
}

bool VerifyModuleIdentity(const std::vector<unsigned char> &image, const dl_phdr_info &module,
	const ElfW(Ehdr) &header, std::string &error)
{
	bool identity_matches = false;
	for (size_t index = 0; index < header.e_phnum; index++)
	{
		ElfW(Phdr) segment;
		ReadValue(image, header.e_phoff + index * sizeof(segment), segment);
		if (std::memcmp(&segment, &module.dlpi_phdr[index], sizeof(segment)) != 0)
			return Fail(error, "Logic file program headers differ from the loaded module");
		if (segment.p_type != PT_NOTE)
			continue;
		uintptr_t note_address;
		if (!CheckedAddressAdd(module.dlpi_addr, segment.p_vaddr, note_address) ||
			!InSegment(module, note_address, segment.p_filesz, PF_R) ||
			!FileRange(image, segment.p_offset, segment.p_filesz))
			return Fail(error, "Invalid ELF note range");
		std::vector<unsigned char> file_id;
		std::vector<unsigned char> loaded_id;
		if (ReadBuildId(image.data() + segment.p_offset, segment.p_filesz, file_id))
		{
			if (!ReadBuildId(reinterpret_cast<const unsigned char *>(note_address),
				segment.p_filesz, loaded_id) || file_id != loaded_id)
				return Fail(error, "Logic file build ID differs from the loaded module; restart after updating SourceMod");
			identity_matches = true;
		}
	}
	if (!identity_matches)
		return Fail(error, "Cannot establish logic file/loaded module identity without a GNU build ID");

	return true;
}

bool ReadFunctionSymbols(const std::vector<unsigned char> &image, const ElfW(Ehdr) &header,
	ElfW(Sym) &scanner_symbol, ElfW(Sym) &loader_symbol, std::string &error)
{
	for (size_t index = 0; index < header.e_shnum; index++)
	{
		ElfW(Shdr) symbols;
		ReadValue(image, header.e_shoff + index * sizeof(symbols), symbols);
		if (symbols.sh_type != SHT_SYMTAB)
			continue;
		ElfW(Shdr) strings;
		if (symbols.sh_entsize != sizeof(ElfW(Sym)) || symbols.sh_size % sizeof(ElfW(Sym)) ||
			symbols.sh_link >= header.e_shnum || !FileRange(image, symbols.sh_offset, symbols.sh_size) ||
			!ReadValue(image, header.e_shoff + size_t(symbols.sh_link) * sizeof(strings), strings) ||
			strings.sh_type != SHT_STRTAB || !FileRange(image, strings.sh_offset, strings.sh_size))
			return Fail(error, "Invalid ELF symbol/string table");
		for (size_t offset = 0; offset < symbols.sh_size; offset += sizeof(ElfW(Sym)))
		{
			ElfW(Sym) symbol;
			ReadValue(image, symbols.sh_offset + offset, symbol);
			if (symbol.st_name >= strings.sh_size)
				return Fail(error, "ELF symbol name is outside the string table");
			const char *name = reinterpret_cast<const char *>(image.data() + strings.sh_offset + symbol.st_name);
			if (!std::memchr(name, '\0', strings.sh_size - symbol.st_name))
				return Fail(error, "Unterminated ELF symbol name");
			ElfW(Sym) *selected = nullptr;
			if (std::strcmp(name, kScannerSymbol) == 0)
				selected = &scanner_symbol;
			else if (std::strcmp(name, kTargetSymbol) == 0)
				selected = &loader_symbol;
			if (!selected)
				continue;
			if (ELF32_ST_TYPE(symbol.st_info) != STT_FUNC || !symbol.st_size ||
				symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= header.e_shnum ||
				(selected->st_size && (selected->st_value != symbol.st_value || selected->st_size != symbol.st_size)))
				return Fail(error, "Invalid or ambiguous loader/scanner function symbol");
			*selected = symbol;
		}
	}
	return true;
}

bool ResolveFunctionRanges(const dl_phdr_info &module, const ElfW(Sym) &scanner_symbol,
	const ElfW(Sym) &loader_symbol, TargetCheck &target, std::string &error)
{
	uintptr_t scanner_address;
	uintptr_t loader_address;
	if (!scanner_symbol.st_size || scanner_symbol.st_size > kMaxScannerBytes ||
		!loader_symbol.st_size || loader_symbol.st_size > kMaxScannerBytes ||
		!CheckedAddressAdd(module.dlpi_addr, scanner_symbol.st_value, scanner_address) ||
		!CheckedAddressAdd(module.dlpi_addr, loader_symbol.st_value, loader_address) ||
		!InSegment(module, scanner_address, scanner_symbol.st_size, PF_R | PF_X) ||
		!InSegment(module, loader_address, loader_symbol.st_size, PF_R | PF_X))
		return Fail(error, "Missing, stripped, oversized, or non-executable loader/scanner symbols");
	target.loader = reinterpret_cast<void *>(loader_address);
	target.scanner = reinterpret_cast<unsigned char *>(scanner_address);
	target.scanner_size = scanner_symbol.st_size;
	return true;
}
}

bool ReadTargetImage(const std::vector<unsigned char> &image, const dl_phdr_info &module,
	TargetCheck &target, std::string &error)
{
	target = {};
	error.clear();
	ElfW(Ehdr) header;
	ElfW(Sym) scanner_symbol{};
	ElfW(Sym) loader_symbol{};
	return ReadImageHeader(image, module, header, error) &&
		VerifyModuleIdentity(image, module, header, error) &&
		ReadFunctionSymbols(image, header, scanner_symbol, loader_symbol, error) &&
		ResolveFunctionRanges(module, scanner_symbol, loader_symbol, target, error);
}

bool DiscoverTarget(void *module_handle, TargetCheck &target, std::string &error)
{
	target = {};
	link_map *mapping = nullptr;
	if (!module_handle || dlinfo(module_handle, RTLD_DI_LINKMAP, &mapping) != 0 || !mapping)
		return Fail(error, "Cannot inspect loaded SourceMod logic module");
	ModuleSnapshot snapshot{mapping->l_addr};
	dl_iterate_phdr(FindModule, &snapshot);
	if (!snapshot.found)
		return Fail(error, "Cannot find loaded SourceMod logic program headers");
	std::ifstream file(mapping->l_name, std::ios::binary | std::ios::ate);
	if (!file)
		return Fail(error, "Cannot read loaded SourceMod logic file");
	const auto size = file.tellg();
	if (size <= 0 || static_cast<uint64_t>(size) > kMaxLogicFileBytes)
		return Fail(error, "Invalid or oversized SourceMod logic file");
	std::vector<unsigned char> image(static_cast<size_t>(size));
	file.seekg(0);
	if (!file.read(reinterpret_cast<char *>(image.data()), image.size()))
		return Fail(error, "Cannot read complete SourceMod logic file");
	return ReadTargetImage(image, snapshot.info, target, error) && ValidateScanCode(target, error);
}
}

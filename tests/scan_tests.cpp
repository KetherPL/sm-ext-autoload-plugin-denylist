// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan_hook.h"
#include <safetyhook/mid_hook.hpp>
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace AutoloadDenylist;
namespace
{
Denylist denylist;
uintptr_t resume_address;
int loader_calls = 0;
int iterator_calls = 0;
void *last_manager = nullptr;
std::string last_plugin;

void Filter(safetyhook::Context &context)
{
	FilterScanCall(context, denylist, resume_address);
}

extern "C" int FixtureThree(void *manager, void **result, const char *plugin)
{
	loader_calls++;
	last_manager = manager;
	last_plugin = plugin;
	*result = manager;
	return 0;
}

extern "C" int FixtureFour(void *manager, void **result, const char *plugin, unsigned extra)
{
	assert(extra == 0);
	return FixtureThree(manager, result, plugin);
}

extern "C" void FixtureNext(void *) { iterator_calls++; }
extern "C" int ScanThree(void *, void **, const char *, void *);
extern "C" int ScanFour(void *, void **, const char *, void *);
extern "C" char ScanThreeEnd, ScanFourEnd;

// Model the public IDirectory::NextEntry call and SourceMod's result dispatch.
#define SCANNER(name, loader, reservation, extra) \
asm(".text\n.global " #name "\n.type " #name ",@function\n" #name ":\n" \
	"push %ebp\nmov %esp,%ebp\npush %esi\npush %edi\nsub $16,%esp\n" \
	"mov 16(%ebp),%edi\nmov 20(%ebp),%esi\njmp " #name "Setup\n" \
	#name "Iterate:\nmov (%esi),%eax\nsub $12,%esp\npush %esi\ncall *12(%eax)\nadd $16,%esp\n" \
	"mov $3,%eax\njmp " #name "Done\n" \
	#name "Setup:\nmovl $0,-12(%ebp)\nsub $" #reservation ",%esp\n" extra \
	"push %edi\nlea -12(%ebp),%eax\npush %eax\npush 8(%ebp)\ncall " #loader "\n" \
	"add $32,%esp\ncmp $2,%eax\nje " #name "Failure\ntest %eax,%eax\njnz " #name "Iterate\n" \
	"mov -12(%ebp),%eax\nmov 12(%ebp),%edx\nmov %eax,(%edx)\nxor %eax,%eax\njmp " #name "Done\n" \
	#name "Failure:\nmov $2,%eax\n" #name "Done:\nadd $16,%esp\npop %edi\npop %esi\nleave\nret\n" \
	".global " #name "End\n" #name "End:\n.size " #name ",.-" #name "\n");
SCANNER(ScanThree, FixtureThree, 20, "")
SCANNER(ScanFour, FixtureFour, 16, "push $0\n")
#undef SCANNER

using Scanner = int (*)(void *, void **, const char *, void *);

void InitializeDenylist()
{
	denylist.ReadSMC_ParseStart();
	denylist.ReadSMC_NewSection(nullptr, "AutoloadPluginDenylist");
	denylist.ReadSMC_NewSection(nullptr, "Plugins");
	denylist.ReadSMC_KeyValue(nullptr, "blocked.smx", "1");
	denylist.ReadSMC_LeavingSection(nullptr);
	denylist.ReadSMC_NewSection(nullptr, "Directories");
	denylist.ReadSMC_KeyValue(nullptr, "legacy", "1");
	denylist.ReadSMC_LeavingSection(nullptr);
	denylist.ReadSMC_LeavingSection(nullptr);
	denylist.ReadSMC_ParseEnd(false, false);
	assert(denylist.IsComplete());
}

void TestContext()
{
	uintptr_t arguments[] = {0, 0, reinterpret_cast<uintptr_t>("allowed.smx"), 0};
	safetyhook::Context context;
	std::memset(&context, 0xa5, sizeof(context));
	context.esp = reinterpret_cast<uintptr_t>(arguments);
	const auto original = context;
	assert(!FilterScanCall(context, denylist, 1));
	assert(std::memcmp(&context, &original, sizeof(context)) == 0);
	arguments[2] = reinterpret_cast<uintptr_t>("blocked.smx");
	assert(FilterScanCall(context, denylist, 1));
	assert(context.eax == kLoadNeverLoad && context.eip == 1 && context.esp == original.esp);
}

void TestDiscoveryFailures(TargetCheck verified)
{
	const size_t call_offset = verified.call - verified.scanner;
	std::vector<unsigned char> image(verified.scanner, verified.scanner + verified.scanner_size);
	auto prepare = [&]()
	{
		image.assign(verified.scanner, verified.scanner + verified.scanner_size);
		image.reserve(verified.scanner_size + kRelativeCallSize);
		const uint32_t displacement = reinterpret_cast<uintptr_t>(verified.loader) -
			(reinterpret_cast<uintptr_t>(image.data()) + call_offset + kRelativeCallSize);
		std::memcpy(image.data() + call_offset + 1, &displacement, sizeof(displacement));
		return TargetCheck{verified.loader, image.data(), image.size()};
	};
	std::string error;
	auto target = prepare();
	assert(ValidateScanCode(target, error));
	target = prepare();
	image[call_offset] = 0x90;
	assert(!ValidateScanCode(target, error) && !target.call && !target.resume_address);
	target = prepare();
	image[call_offset - 1] = 12; // manager argument must be [ebp+8].
	assert(!ValidateScanCode(target, error));
	target = prepare();
	const std::array<unsigned char, 7> initialization{0xc7, 0x45, 0xf4, 0, 0, 0, 0};
	auto initializer = std::search(image.begin(), image.end(), initialization.begin(), initialization.end());
	assert(initializer != image.end());
	initializer[3] = 1;
	assert(!ValidateScanCode(target, error));
	target = prepare();
	initializer = std::search(image.begin(), image.end(), initialization.begin(), initialization.end());
	auto entry_jump = std::find(image.begin(), initializer, 0xeb);
	assert(entry_jump != initializer);
	entry_jump[1] = static_cast<unsigned char>((initializer - entry_jump) + initialization.size() - 2);
	assert(!ValidateScanCode(target, error) && error.find("bypasses") != std::string::npos);
	target = prepare();
	const std::array<unsigned char, 3> condition{0x85, 0xc0, 0x75};
	auto test = std::search(image.begin() + call_offset + kRelativeCallSize, image.end(), condition.begin(), condition.end());
	assert(test != image.end());
	test[2] = 0x74;
	assert(!ValidateScanCode(target, error));
	target = prepare();
	target.scanner_size = call_offset + kRelativeCallSize - 1;
	assert(!ValidateScanCode(target, error));
	target = prepare();
	image.push_back(0xe8);
	const uint32_t displacement = reinterpret_cast<uintptr_t>(verified.loader) -
		(reinterpret_cast<uintptr_t>(image.data()) + image.size() + sizeof(uint32_t));
	const auto *bytes = reinterpret_cast<const unsigned char *>(&displacement);
	image.insert(image.end(), bytes, bytes + sizeof(displacement));
	// A vector reallocation also changes the first call's relative displacement.
	const uint32_t first_displacement = reinterpret_cast<uintptr_t>(verified.loader) -
		(reinterpret_cast<uintptr_t>(image.data()) + call_offset + kRelativeCallSize);
	std::memcpy(image.data() + call_offset + 1, &first_displacement, sizeof(first_displacement));
	target = {verified.loader, image.data(), image.size()};
	assert(!ValidateScanCode(target, error) && error.find("multiple") != std::string::npos);
	target = {verified.loader, reinterpret_cast<unsigned char *>(UINTPTR_MAX - 1), 4};
	assert(!ValidateScanCode(target, error));
}

void TestScanner(Scanner scanner, const void *end, void *loader)
{
	TargetCheck target{loader, reinterpret_cast<unsigned char *>(scanner),
		reinterpret_cast<uintptr_t>(end) - reinterpret_cast<uintptr_t>(scanner)};
	std::string error;
	if (!ValidateScanCode(target, error))
	{
		std::fprintf(stderr, "Fixture discovery failed: %s\n", error.c_str());
		std::abort();
	}
	TestDiscoveryFailures(target);
	resume_address = target.resume_address;
	std::vector<unsigned char> original(target.scanner, target.scanner + target.scanner_size);
	auto created = safetyhook::MidHook::create(target.call, &Filter, safetyhook::MidHook::StartDisabled);
	assert(created);
	auto hook = std::move(created.value());
	assert(hook.original_bytes().size() == kRelativeCallSize && hook.enable());
	std::array<void *, 4> vtable{nullptr, nullptr, nullptr, reinterpret_cast<void *>(&FixtureNext)};
	void *iterator = vtable.data();
	int manager = 0;
	void *result = nullptr;
	loader_calls = iterator_calls = 0;
	assert(scanner(&manager, &result, "blocked.smx", &iterator) == kLoadNeverLoad);
	assert(loader_calls == 0 && iterator_calls == 1 && result == nullptr);
	assert(scanner(&manager, &result, "legacy/nested/a.smx", &iterator) == kLoadNeverLoad);
	assert(loader_calls == 0 && iterator_calls == 2);
	assert(scanner(&manager, &result, "allowed.smx", &iterator) == 0);
	assert(loader_calls == 1 && iterator_calls == 2 && result == &manager && last_manager == &manager);
	assert(FixtureThree(&manager, &result, "blocked.smx") == 0 && loader_calls == 2);
	hook.reset();
	assert(std::memcmp(original.data(), target.scanner, original.size()) == 0);
	assert(scanner(&manager, &result, "blocked.smx", &iterator) == 0 && loader_calls == 3);
}
}

int main()
{
	InitializeDenylist();
	TestContext();
	TestScanner(&ScanThree, &ScanThreeEnd, reinterpret_cast<void *>(&FixtureThree));
	TestScanner(&ScanFour, &ScanFourEnd, reinterpret_cast<void *>(&FixtureFour));
	std::puts("Runtime discovery, rejection, three/four-argument filtering, manual loads, and mid-hook restoration passed");
}

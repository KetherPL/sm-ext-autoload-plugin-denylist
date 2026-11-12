// SPDX-License-Identifier: GPL-3.0-or-later
#include "verified_target.h"
#include <Zydis.h>
#include <algorithm>
#include <array>
#include <cstring>

namespace AutoloadDenylist
{
namespace
{
constexpr size_t kMaxDecodedInstructions = 4096;
constexpr size_t kMaxArgumentInstructions = 12;
constexpr size_t kMaxReturnInstructions = 8;
constexpr int64_t kDirectoryNextEntryOffset = 3 * sizeof(uint32_t);

struct Instruction
{
	size_t offset;
	ZydisDecodedInstruction decoded{};
	std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
};

bool Register(const ZydisDecodedOperand &operand, ZydisRegister value)
{
	return operand.type == ZYDIS_OPERAND_TYPE_REGISTER && operand.reg.value == value;
}

bool Immediate(const ZydisDecodedOperand &operand, uint64_t value)
{
	return operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !operand.imm.is_relative && operand.imm.value.u == value;
}

bool Memory(const ZydisDecodedOperand &operand, ZydisRegister base, int64_t displacement)
{
	return operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == base &&
		operand.mem.index == ZYDIS_REGISTER_NONE && operand.mem.disp.value == displacement && operand.size == 32;
}

bool StackAdjustment(const Instruction &instruction, ZydisMnemonic mnemonic, uint64_t bytes)
{
	return instruction.decoded.mnemonic == mnemonic && Register(instruction.operands[0], ZYDIS_REGISTER_ESP) &&
		Immediate(instruction.operands[1], bytes);
}

bool RelativeTarget(const TargetCheck &target, const Instruction &instruction, uintptr_t &address)
{
	const auto &operand = instruction.operands[0];
	if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operand.imm.is_relative)
		return false;
	ZyanU64 absolute;
	if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction.decoded, &operand,
		reinterpret_cast<uintptr_t>(target.scanner) + instruction.offset, &absolute)))
		return false;
	// Near transfers wrap at 32 bits on i386. Zydis only applies the 16-bit mask.
	if (instruction.decoded.machine_mode == ZYDIS_MACHINE_MODE_LEGACY_32)
		absolute &= UINT32_MAX;
	if (absolute > std::numeric_limits<uintptr_t>::max())
		return false;
	address = static_cast<uintptr_t>(absolute);
	return true;
}

size_t InstructionAt(const std::vector<Instruction> &instructions, size_t offset)
{
	const auto found = std::lower_bound(instructions.begin(), instructions.end(), offset,
		[](const Instruction &instruction, size_t position) { return instruction.offset < position; });
	return found != instructions.end() && found->offset == offset ? size_t(found - instructions.begin()) : instructions.size();
}

bool VerifyArguments(const std::vector<Instruction> &instructions, size_t call_index,
	uint64_t &cleanup_bytes, size_t &setup_start)
{
	if (instructions.size() < 2 || instructions[0].decoded.mnemonic != ZYDIS_MNEMONIC_PUSH ||
		!Register(instructions[0].operands[0], ZYDIS_REGISTER_EBP) ||
		instructions[1].decoded.mnemonic != ZYDIS_MNEMONIC_MOV ||
		!Register(instructions[1].operands[0], ZYDIS_REGISTER_EBP) ||
		!Register(instructions[1].operands[1], ZYDIS_REGISTER_ESP))
		return false;
	std::vector<size_t> pushes;
	size_t adjustment = call_index;
	for (size_t distance = 1; distance <= kMaxArgumentInstructions && distance <= call_index; distance++)
	{
		const size_t index = call_index - distance;
		const auto &instruction = instructions[index];
		if (instruction.decoded.mnemonic == ZYDIS_MNEMONIC_SUB &&
			Register(instruction.operands[0], ZYDIS_REGISTER_ESP) &&
			instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			adjustment = index;
			break;
		}
		if (instruction.decoded.mnemonic == ZYDIS_MNEMONIC_PUSH && instruction.decoded.operand_width == 32)
			pushes.push_back(index);
		else if ((instruction.decoded.mnemonic != ZYDIS_MNEMONIC_MOV &&
			instruction.decoded.mnemonic != ZYDIS_MNEMONIC_LEA) ||
			instruction.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
			Register(instruction.operands[0], ZYDIS_REGISTER_ESP) ||
			Register(instruction.operands[0], ZYDIS_REGISTER_EBP))
			return false;
	}
	if (adjustment == call_index || (pushes.size() != 3 && pushes.size() != 4) ||
		!Memory(instructions[pushes[0]].operands[0], ZYDIS_REGISTER_EBP, 8))
		return false;
	const auto &result = instructions[pushes[1]].operands[0];
	const auto &path = instructions[pushes[2]].operands[0];
	if (result.type != ZYDIS_OPERAND_TYPE_REGISTER || path.type != ZYDIS_OPERAND_TYPE_REGISTER ||
		result.size != 32 || path.size != 32 || Register(path, ZYDIS_REGISTER_ESP) ||
		Register(path, ZYDIS_REGISTER_EBP) || (pushes.size() == 4 && !Immediate(instructions[pushes[3]].operands[0], 0)))
		return false;

	// The result argument must be the address of a zero-initialized local slot.
	int64_t result_slot = 0;
	for (size_t index = pushes[1]; index-- > adjustment;)
	{
		const auto &instruction = instructions[index];
		if (!Register(instruction.operands[0], result.reg.value))
			continue;
		if (instruction.decoded.mnemonic != ZYDIS_MNEMONIC_LEA ||
			instruction.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
			instruction.operands[1].mem.base != ZYDIS_REGISTER_EBP ||
			instruction.operands[1].mem.index != ZYDIS_REGISTER_NONE || instruction.operands[1].mem.disp.value >= 0)
			return false;
		result_slot = instruction.operands[1].mem.disp.value;
		break;
	}
	bool initialized = false;
	for (size_t distance = 1; result_slot && distance <= 3 && distance <= adjustment; distance++)
	{
		const auto &instruction = instructions[adjustment - distance];
		if (instruction.decoded.mnemonic == ZYDIS_MNEMONIC_MOV &&
			Memory(instruction.operands[0], ZYDIS_REGISTER_EBP, result_slot))
		{
			initialized = Immediate(instruction.operands[1], 0);
			setup_start = adjustment - distance;
			break;
		}
	}
	cleanup_bytes = instructions[adjustment].operands[1].imm.value.u + pushes.size() * sizeof(uint32_t);
	return initialized && cleanup_bytes == 32;
}

bool VerifyIteration(const std::vector<Instruction> &instructions, size_t index)
{
	if (index + 5 > instructions.size())
		return false;
	const auto &load = instructions[index];
	const auto &destination = load.operands[0];
	const auto &source = load.operands[1];
	if (load.decoded.mnemonic != ZYDIS_MNEMONIC_MOV || destination.type != ZYDIS_OPERAND_TYPE_REGISTER ||
		source.type != ZYDIS_OPERAND_TYPE_MEMORY || source.mem.base == ZYDIS_REGISTER_NONE ||
		source.mem.base == ZYDIS_REGISTER_EBP || source.mem.base == ZYDIS_REGISTER_ESP ||
		!Memory(source, source.mem.base, 0))
		return false;
	const auto &push = instructions[index + 2];
	const auto &call = instructions[index + 3];
	return StackAdjustment(instructions[index + 1], ZYDIS_MNEMONIC_SUB, 12) &&
		push.decoded.mnemonic == ZYDIS_MNEMONIC_PUSH && Register(push.operands[0], source.mem.base) &&
		call.decoded.mnemonic == ZYDIS_MNEMONIC_CALL &&
		Memory(call.operands[0], destination.reg.value, kDirectoryNextEntryOffset) &&
		StackAdjustment(instructions[index + 4], ZYDIS_MNEMONIC_ADD, 16);
}

bool VerifySkipPath(const TargetCheck &target, const std::vector<Instruction> &instructions,
	size_t call_index, uint64_t cleanup_bytes)
{
	size_t index = call_index + 1;
	if (index >= instructions.size() || !StackAdjustment(instructions[index++], ZYDIS_MNEMONIC_ADD, cleanup_bytes))
		return false;
	bool flags_known = false;
	bool zero = false;
	for (size_t step = 0; step < kMaxReturnInstructions && index < instructions.size(); step++)
	{
		const auto &instruction = instructions[index];
		const auto &left = instruction.operands[0];
		const auto &right = instruction.operands[1];
		const auto mnemonic = instruction.decoded.mnemonic;
		if (mnemonic == ZYDIS_MNEMONIC_CMP && Register(left, ZYDIS_REGISTER_EAX) && Immediate(right, 2))
		{
			zero = false;
			flags_known = true;
			index++;
		}
		else if (mnemonic == ZYDIS_MNEMONIC_TEST &&
			(Register(left, ZYDIS_REGISTER_EAX) || Register(left, ZYDIS_REGISTER_AL)))
		{
			if (Register(right, left.reg.value))
				zero = false;
			else if (right.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !right.imm.is_relative)
				zero = (kLoadNeverLoad & right.imm.value.u) == 0;
			else
				return false;
			flags_known = true;
			index++;
		}
		else if (flags_known && (mnemonic == ZYDIS_MNEMONIC_JZ || mnemonic == ZYDIS_MNEMONIC_JNZ))
		{
			if ((mnemonic == ZYDIS_MNEMONIC_JZ) != zero)
			{
				index++;
				continue;
			}
			uintptr_t address;
			if (!RelativeTarget(target, instruction, address) || address < reinterpret_cast<uintptr_t>(target.scanner))
				return false;
			const size_t destination = InstructionAt(instructions, address - reinterpret_cast<uintptr_t>(target.scanner));
			if (destination < call_index)
				return VerifyIteration(instructions, destination);
			index = destination;
		}
		else
			return false;
	}
	return false;
}
}

bool ValidateScanCode(TargetCheck &target, std::string &error)
{
	target.call = nullptr;
	target.resume_address = 0;
	auto fail = [&error](const char *message) { error = message; return false; };
	if (!target.scanner || !target.loader || !target.scanner_size || target.scanner_size > kMaxScannerBytes)
		return fail("Invalid scanner function range");
	uintptr_t end;
	if (!CheckedAddressAdd(reinterpret_cast<uintptr_t>(target.scanner), target.scanner_size, end))
		return fail("Scanner function range overflows");
	ZydisDecoder decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)))
		return fail("Cannot initialize i386 instruction decoder");
	std::vector<Instruction> instructions;
	for (size_t offset = 0; offset < target.scanner_size;)
	{
		if (instructions.size() == kMaxDecodedInstructions)
			return fail("Scanner exceeds instruction-count limit");
		Instruction instruction{};
		instruction.offset = offset;
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, target.scanner + offset,
			target.scanner_size - offset, &instruction.decoded, instruction.operands.data())) ||
			!instruction.decoded.length || instruction.decoded.length > target.scanner_size - offset)
			return fail("Cannot decode complete scanner function");
		offset += instruction.decoded.length;
		instructions.push_back(instruction);
	}
	size_t call_index = instructions.size();
	for (size_t index = 0; index < instructions.size(); index++)
	{
		const auto &instruction = instructions[index];
		uintptr_t address;
		if (instruction.decoded.mnemonic != ZYDIS_MNEMONIC_CALL ||
			!RelativeTarget(target, instruction, address) || address != reinterpret_cast<uintptr_t>(target.loader))
			continue;
		if (call_index != instructions.size())
			return fail("Scanner contains multiple loader calls");
		if (instruction.decoded.length != kRelativeCallSize || target.scanner[instruction.offset] != 0xe8)
			return fail("Unrecognized loader call encoding");
		call_index = index;
	}
	if (call_index == instructions.size())
		return fail("Scanner has no direct call to the internal loader");
	const uintptr_t call_address = reinterpret_cast<uintptr_t>(target.scanner) + instructions[call_index].offset;
	for (const auto &instruction : instructions)
	{
		uintptr_t address;
		if ((instruction.decoded.meta.category == ZYDIS_CATEGORY_COND_BR ||
			instruction.decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR) &&
			RelativeTarget(target, instruction, address) && address > call_address && address < call_address + kRelativeCallSize)
			return fail("A branch enters the middle of the loader call");
	}
	uint64_t cleanup_bytes;
	size_t setup_start = 0;
	if (!VerifyArguments(instructions, call_index, cleanup_bytes, setup_start))
		return fail("Unrecognized scanner argument setup");
	const uintptr_t setup_address = reinterpret_cast<uintptr_t>(target.scanner) + instructions[setup_start].offset;
	for (const auto &instruction : instructions)
	{
		uintptr_t address;
		if ((instruction.decoded.meta.category == ZYDIS_CATEGORY_COND_BR ||
			instruction.decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR) &&
			RelativeTarget(target, instruction, address) && address > setup_address && address <= call_address)
			return fail("A branch bypasses validated argument initialization");
	}
	if (!VerifySkipPath(target, instructions, call_index, cleanup_bytes))
		return fail("Cannot verify that a denied load resumes directory iteration");
	target.call = reinterpret_cast<unsigned char *>(call_address);
	target.resume_address = call_address + kRelativeCallSize;
	error.clear();
	return true;
}
}

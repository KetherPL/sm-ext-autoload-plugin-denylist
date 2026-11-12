// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "denylist.h"
#include "verified_target.h"
#include <safetyhook/context.hpp>

#if !defined(__i386__)
#error The validated scan argument layout supports Linux i386 only.
#endif

namespace AutoloadDenylist
{
inline const char *ScanPluginPath(const safetyhook::Context &context)
{
	// Before CALL, cdecl arguments are manager, result slot, plugin path.
	return reinterpret_cast<const char *const *>(context.esp)[2];
}

inline void SkipScanCall(safetyhook::Context &context, uintptr_t resume_address)
{
	context.eax = kLoadNeverLoad;
	context.eip = resume_address;
}

inline bool FilterScanCall(safetyhook::Context &context, const Denylist &denylist, uintptr_t resume_address)
{
	if (!denylist.Blocks(ScanPluginPath(context)))
		return false;
	SkipScanCall(context, resume_address);
	return true;
}
}

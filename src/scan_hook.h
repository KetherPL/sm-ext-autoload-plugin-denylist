// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "denylist.h"
#include "verified_target.h"
#include <safetyhook/context.hpp>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <sys/uio.h>
#include <unistd.h>

#if !defined(__i386__)
#error The validated scan argument layout supports Linux i386 only.
#endif

namespace AutoloadDenylist
{
using ScanPathBuffer = std::array<char, kMaxRelativePath + 1>;

enum class ScanFilterResult
{
	Allowed,
	Denied,
	InvalidPath
};

inline bool ReadScanPluginPath(uintptr_t candidate, ScanPathBuffer &buffer)
{
	buffer[0] = '\0';
	static const long page_size = sysconf(_SC_PAGESIZE);
	if (!candidate || page_size <= 0)
		return false;
	size_t copied = 0;
	while (copied < buffer.size())
	{
		uintptr_t address;
		if (!CheckedAddressAdd(candidate, copied, address))
			break;
		const size_t page_remaining = static_cast<size_t>(page_size) - address % static_cast<size_t>(page_size);
		const size_t chunk_size = std::min(buffer.size() - copied, page_remaining);
		iovec local{buffer.data() + copied, chunk_size};
		iovec remote{reinterpret_cast<void *>(address), chunk_size};
		ssize_t bytes_read;
		do
		{
			// The kernel copies readable bytes without dereferencing an untrusted
			// candidate in this process. No mapping cache or signal handler is used.
			bytes_read = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
		} while (bytes_read < 0 && errno == EINTR);
		if (bytes_read <= 0 || static_cast<size_t>(bytes_read) > chunk_size)
			break;
		if (std::memchr(buffer.data() + copied, '\0', static_cast<size_t>(bytes_read)))
			return true;
		copied += static_cast<size_t>(bytes_read);
		if (static_cast<size_t>(bytes_read) != chunk_size)
			break;
	}
	buffer[0] = '\0';
	return false;
}

inline uintptr_t ScanPluginAddress(const safetyhook::Context &context)
{
	// Before CALL, cdecl arguments are manager, result slot, plugin path.
	return reinterpret_cast<const uintptr_t *>(context.esp)[2];
}

inline void SkipScanCall(safetyhook::Context &context, uintptr_t resume_address)
{
	context.eax = kLoadNeverLoad;
	context.eip = resume_address;
}

inline ScanFilterResult FilterScanCall(safetyhook::Context &context, const Denylist &denylist,
	uintptr_t resume_address, ScanPathBuffer &plugin_path)
{
	if (!ReadScanPluginPath(ScanPluginAddress(context), plugin_path))
	{
		SkipScanCall(context, resume_address);
		return ScanFilterResult::InvalidPath;
	}
	if (!denylist.Blocks(plugin_path.data()))
		return ScanFilterResult::Allowed;
	SkipScanCall(context, resume_address);
	return ScanFilterResult::Denied;
}
}

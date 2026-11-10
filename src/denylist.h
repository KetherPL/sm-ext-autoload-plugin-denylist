// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <ITextParsers.h>
#include <cstring>
#include <string>
#include <unordered_set>

namespace AutoloadDenylist
{
constexpr size_t kMaxRelativePath = 4095;

inline bool NormalizePath(const char *input, bool directory, std::string &normalized)
{
	normalized.clear();
	if (!input || !*input || input[0] == '/' || input[0] == '\\')
		return false;
	std::string component;
	for (size_t index = 0; ; index++)
	{
		if (index > kMaxRelativePath)
			return false;
		const unsigned char character = input[index];
		if (character == '/' || character == '\\' || character == '\0')
		{
			if (component == "..")
				return false;
			if (!component.empty() && component != ".")
			{
				if (!normalized.empty())
					normalized += '/';
				normalized += component;
			}
			component.clear();
			if (!character)
				break;
			if (!directory && !input[index + 1])
				return false;
		} else {
			if (character < 32 || character == 127 || character == ':' ||
				character == '*' || character == '?')
				return false;
			component += static_cast<char>(character);
		}
	}
	return !normalized.empty() && (directory ||
		(normalized.size() >= 4 && normalized.compare(normalized.size() - 4, 4, ".smx") == 0));
}

class Denylist final : public SourceMod::ITextListener_SMC
{
public:
	void ReadSMC_ParseStart() override
	{
		plugins_.clear();
		directories_.clear();
		error_.clear();
		depth_ = 0;
		root_seen_ = false;
		plugins_seen_ = false;
		directories_seen_ = false;
		complete_ = false;
	}

	SourceMod::SMCResult ReadSMC_NewSection(const SourceMod::SMCStates *, const char *name) override
	{
		if (depth_ == 0 && !root_seen_ && std::strcmp(name, "AutoloadPluginDenylist") == 0)
			root_seen_ = true;
		else if (depth_ == 1 && !plugins_seen_ && std::strcmp(name, "Plugins") == 0)
		{
			plugins_seen_ = true;
			in_directories_ = false;
		}
		else if (depth_ == 1 && !directories_seen_ && std::strcmp(name, "Directories") == 0)
		{
			directories_seen_ = true;
			in_directories_ = true;
		}
		else
			return Fail("Unknown, duplicate, or nested config section");
		depth_++;
		return SourceMod::SMCResult_Continue;
	}

	SourceMod::SMCResult ReadSMC_KeyValue(const SourceMod::SMCStates *, const char *key,
		const char *value) override
	{
		if (depth_ != 2 || !value || (std::strcmp(value, "0") && std::strcmp(value, "1")))
			return Fail("Entries must be inside Plugins/Directories and use value 0 or 1");
		std::string normalized;
		if (!NormalizePath(key, in_directories_, normalized))
			return Fail("Invalid relative path (plugins require a .smx suffix)");
		if (std::strcmp(value, "1") == 0)
			(in_directories_ ? directories_ : plugins_).insert(std::move(normalized));
		return SourceMod::SMCResult_Continue;
	}

	SourceMod::SMCResult ReadSMC_LeavingSection(const SourceMod::SMCStates *) override
	{
		if (!depth_)
			return Fail("Unexpected closing section");
		depth_--;
		return SourceMod::SMCResult_Continue;
	}

	void ReadSMC_ParseEnd(bool halted, bool failed) override
	{
		complete_ = !halted && !failed && root_seen_ && !depth_ && error_.empty();
	}

	bool IsComplete() const { return complete_; }
	const std::string &Error() const { return error_; }
	size_t PluginCount() const { return plugins_.size(); }
	size_t DirectoryCount() const { return directories_.size(); }

	bool Blocks(const char *plugin) const
	{
		std::string normalized;
		if (!NormalizePath(plugin, false, normalized))
			return false;
		if (plugins_.count(normalized))
			return true;
		// Look up directory ancestors, preserving component boundaries.
		for (size_t separator = normalized.rfind('/'); separator != std::string::npos;
			separator = normalized.rfind('/'))
		{
			normalized.resize(separator);
			if (directories_.count(normalized))
				return true;
		}
		return false;
	}

private:
	SourceMod::SMCResult Fail(const char *message)
	{
		error_ = message;
		return SourceMod::SMCResult_HaltFail;
	}

	std::unordered_set<std::string> plugins_;
	std::unordered_set<std::string> directories_;
	std::string error_;
	unsigned int depth_ = 0;
	bool root_seen_ = false;
	bool plugins_seen_ = false;
	bool directories_seen_ = false;
	bool in_directories_ = false;
	bool complete_ = false;
};
}

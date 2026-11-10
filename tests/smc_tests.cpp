// SPDX-License-Identifier: GPL-3.0-or-later
#include "denylist.h"
#include "TextParsers.h"
#include <cassert>
#include <cstdio>
#include <cstring>

SMGlobalClass *SMGlobalClass::head = nullptr;
SourceMod::IShareSys *sharesys = nullptr;
SourceMod::ILibrarySys *libsys = nullptr;

int main(int argc, char **argv)
{
	assert(argc == 2);
	TextParsers parser;
	AutoloadDenylist::Denylist config;
	SourceMod::SMCStates states{};
	assert(parser.ParseFile_SMC(argv[1], &config, &states) == SourceMod::SMCError_Okay);
	assert(config.IsComplete() && config.PluginCount() == 0 && config.DirectoryCount() == 0);
	const char *valid = R"cfg(
// Actual SourceMod SMC syntax with independent plugin and directory sections.
"AutoloadPluginDenylist"
{
    "Plugins"
    {
        "folder/plugin.smx" "1"
        "allowed.smx" "0"
    }
    "Directories"
    {
        "old/" "1"
    }
}
)cfg";
	char error[256]{};
	assert(parser.ParseSMCStream(valid, std::strlen(valid), &config, &states,
		error, sizeof(error)) == SourceMod::SMCError_Okay);
	assert(config.IsComplete() && config.Blocks("folder/plugin.smx"));
	assert(config.Blocks("old/nested/plugin.smx") && !config.Blocks("allowed.smx"));
	for (const char *invalid : {
		"", "\"WrongRoot\"\n{\n}\n",
		"\"AutoloadPluginDenylist\"\n{\n\"Plugins\"\n{\n\"a.smx\" \"yes\"\n}\n}\n",
		"\"AutoloadPluginDenylist\"\n{\n\"Plugins\"\n{\n\"../a.smx\" \"1\"\n}\n}\n",
		"\"AutoloadPluginDenylist\"\n{\n\"Plugins\"\n{\n}\n\"Plugins\"\n{\n}\n}\n",
		"\"AutoloadPluginDenylist\"\n{\n\"Plugins\"\n{\n",
		"\"AutoloadPluginDenylist\"\n{\n}\n\"AutoloadPluginDenylist\"\n{\n}\n",
		"\"AutoloadPluginDenylist\"\n{\n\"Directories\"\n{\n\"/\" \"1\"\n}\n}\n"})
	{
		const auto result = parser.ParseSMCStream(invalid, std::strlen(invalid), &config,
			&states, error, sizeof(error));
		assert(result != SourceMod::SMCError_Okay || !config.IsComplete());
	}
	std::puts("SourceMod SMC parser integration tests passed");
}

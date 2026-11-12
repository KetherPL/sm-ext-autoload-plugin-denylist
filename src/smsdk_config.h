// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#define SMEXT_CONF_NAME "Autoload Plugin Denylist"
#define SMEXT_CONF_DESCRIPTION "Excludes configured plugins and directory trees from automatic loading"
#define SMEXT_CONF_VERSION "2.0.1"
#define SMEXT_CONF_AUTHOR "Kether.pl"
#define SMEXT_CONF_URL "https://kether.pl"
#define SMEXT_CONF_LOGTAG "AUTOLOAD_DENYLIST"
#define SMEXT_CONF_LICENSE "GPL-3.0-or-later"
#define SMEXT_CONF_DATESTRING __DATE__
#define SMEXT_LINK(name) SDKExtension *g_pExtensionIface = name;
#define SMEXT_ENABLE_TEXTPARSERS

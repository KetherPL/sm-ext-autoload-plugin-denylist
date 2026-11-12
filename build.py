#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a Linux i386 SourceMod extension using an existing SourceMod checkout."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sourcemod", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("build"))
    parser.add_argument("--debug", action="store_true", help="Include debug symbols and leave the extension unstripped")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--logic", type=Path, help="With --test, validate and temporarily detour this logic binary in a standalone test process")
    arguments = parser.parse_args()
    project = Path(__file__).resolve().parent
    sourcemod = arguments.sourcemod.resolve()
    output = arguments.output.resolve()
    public = sourcemod / "public"
    safetyhook = public / "safetyhook"
    includes = [project / "src", public, public / "amtl", public / "amtl/amtl",
                sourcemod / "sourcepawn/include", safetyhook / "include", safetyhook / "zydis"]
    for required in [public / "smsdk_ext.cpp", safetyhook / "zydis/Zydis.c"]:
        if not required.is_file():
            parser.error(f"Missing SourceMod dependency: {required}")
    output.mkdir(parents=True, exist_ok=True)
    compiler = os.environ.get("CXX", "g++")
    c_compiler = os.environ.get("CC", "gcc")
    common_flags = ["-m32", "-O2", "-fPIC", "-fvisibility=hidden",
                    "-D_LINUX", "-DPOSIX", "-pthread"]
    if arguments.debug:
        common_flags.append("-g")
    include_flags = [f"-I{directory}" for directory in includes]
    cpp_flags = ["-std=c++17", "-fno-gnu-unique", "-Wall", "-Wextra", "-Wno-unused-parameter"]
    objects = []
    sources = [project / "src/extension.cpp", public / "smsdk_ext.cpp"]
    sources += [safetyhook / "src" / filename for filename in
                ["allocator.cpp", "easy.cpp", "inline_hook.cpp", "mid_hook.cpp",
                 "utility.cpp", "vmt_hook.cpp", "os.linux.cpp"]]
    sources.append(safetyhook / "zydis/Zydis.c")
    for index, source in enumerate(sources):
        object_path = output / f"{index}_{source.stem}.o"
        is_cpp = source.suffix == ".cpp"
        subprocess.run([compiler if is_cpp else c_compiler, *common_flags, *include_flags,
                        *(cpp_flags if is_cpp else ["-std=c11"]), "-c", str(source),
                        "-o", str(object_path)], check=True)
        objects.append(str(object_path))
    exports = output / "exports.map"
    exports.write_text("{ global: GetSMExtAPI; local: *; };\n")
    package = output / "package/addons/sourcemod"
    extensions = package / "extensions"
    extensions.mkdir(parents=True, exist_ok=True)
    library = extensions / "autoload_plugin_denylist.ext.so"
    subprocess.run([compiler, "-m32", "-shared", *objects, "-ldl", "-pthread",
                    "-Wl,-z,defs,-z,relro,-z,now", f"-Wl,--version-script={exports}",
                    *([] if arguments.debug else ["-Wl,--strip-all"]),
                    "-o", str(library)], check=True)
    (extensions / "autoload_plugin_denylist.autoload").write_text("")
    configs = package / "configs"
    configs.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(project / "configs/autoload_plugin_denylist.cfg",
                    configs / "autoload_plugin_denylist.cfg")
    for filename in ["README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]:
        shutil.copyfile(project / filename, output / "package" / filename)
    if arguments.test:
        tests = output / "denylist_tests"
        subprocess.run([compiler, *common_flags, *include_flags, *cpp_flags,
                        str(project / "tests/denylist_tests.cpp"),
                        *[object_path for object_path in objects if not Path(object_path).name.startswith(("0_", "1_"))],
                        "-ldl", "-o", str(tests)], check=True)
        subprocess.run([str(tests)], check=True)
        smc_tests = output / "smc_tests"
        subprocess.run([compiler, *common_flags, *include_flags, *cpp_flags, "-DSM_LOGIC",
                        f"-I{sourcemod / 'core/logic'}", str(project / "tests/smc_tests.cpp"),
                        str(sourcemod / "core/logic/TextParsers.cpp"),
                        "-o", str(smc_tests)], check=True)
        subprocess.run([str(smc_tests), str(project / "configs/autoload_plugin_denylist.cfg")], check=True)
        if arguments.logic:
            logic = arguments.logic.resolve()
            symbols = {}
            for line in subprocess.check_output(["nm", "--defined-only", "--format=posix", str(logic)], text=True).splitlines():
                fields = line.split()
                if len(fields) >= 3:
                    symbols[fields[0]] = fields[2]
            loader_symbol = "_ZN14CPluginManager10LoadPluginEPP7CPluginPKcbN9SourceMod10PluginTypeE"
            scanner_symbol = "_ZN14CPluginManager18LoadPluginsFromDirEPKcS1_"
            if loader_symbol not in symbols or scanner_symbol not in symbols:
                parser.error("Logic binary lacks required loader/scanner symbols")
            logic_tests = output / "logic_tests"
            subprocess.run([compiler, *common_flags, *include_flags, *cpp_flags,
                            str(project / "tests/logic_tests.cpp"),
                            *[object_path for object_path in objects if not Path(object_path).name.startswith(("0_", "1_"))],
                            "-ldl", "-o", str(logic_tests)], check=True)
            subprocess.run([str(logic_tests), str(logic), symbols[loader_symbol], symbols[scanner_symbol], str(library)], check=True)
    print(f"Built {library}")


if __name__ == "__main__":
    main()

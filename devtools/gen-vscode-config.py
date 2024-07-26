#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation
#

"""Visual Studio Code configuration generator script."""

import os
import json
import argparse
import fnmatch
import shutil
from typing import List, Dict, Tuple, Any
from sys import exit as _exit, stderr
from subprocess import run, CalledProcessError, PIPE
from mesonbuild import mparser
from mesonbuild.mesonlib import MesonException


class DPDKBuildTask:
    """A build task for DPDK"""

    def __init__(self, label: str, description: str, param: str):
        # label as it appears in build configuration
        self.label = label
        # description to be given in menu
        self.description = description
        # task-specific configuration parameters
        self.param = param

    def to_json_dict(self) -> Dict[str, Any]:
        """Generate JSON dictionary for this task"""
        return {
            "label": f"Configure {self.label}",
            "detail": self.description,
            "type": "shell",
            "dependsOn": "Remove builddir",
            "command": f"meson setup ${{config:BUILDCONFIG}} {self.param} ${{config:BUILDDIR}}",
            "problemMatcher": [],
            "group": "build"
        }


class CmdlineCtx:
    """POD class to set up command line parameters"""

    def __init__(self):
        self.use_ui = False
        self.use_gdbsudo = False
        self.build_dir: str = ""
        self.dpdk_dir: str = ""
        self.gdb_path: str = ""

        self.avail_configs: List[Tuple[str, str, str]] = []
        self.avail_apps: List[str] = []
        self.avail_examples: List[str] = []
        self.avail_drivers: List[str] = []

        self.enabled_configs: List[Tuple[str, str, str]] = []
        self.enabled_apps: List[str] = []
        self.enabled_examples: List[str] = []
        self.enabled_drivers: List[str] = []

        self.driver_dep_map: Dict[str, List[str]] = {}


class DPDKLaunchTask:
    """A launch task for DPDK"""

    def __init__(self, label: str, exe: str, gdb_path: str):
        # label as it appears in launch configuration
        self.label = label
        # path to executable
        self.exe = exe
        self.gdb_path = gdb_path

    def to_json_dict(self) -> Dict[str, Any]:
        """Generate JSON dictionary for this task"""
        return {
            "name": f"Run {self.label}",
            "type": "cppdbg",
            "request": "launch",
            "program": f"${{config:BUILDDIR}}/{self.exe}",
            "args": [],
            "stopAtEntry": False,
            "cwd": "${workspaceFolder}",
            "externalConsole": False,
            "preLaunchTask": "Build",
            "MIMode": "gdb",
            "miDebuggerPath": self.gdb_path,
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-gdb-set print pretty on",
                    "ignoreFailures": True
                }
            ]
        }


class VSCodeConfig:
    """Configuration for VSCode"""

    def __init__(self, builddir: str, commoncfg: str):
        # where will our build dir be located
        self.builddir = builddir
        # meson configuration common to all configs
        self.commonconfig = commoncfg
        # meson build configurations
        self.build_tasks: List[DPDKBuildTask] = []
        # meson launch configurations
        self.launch_tasks: List[DPDKLaunchTask] = []

    def settings_to_json_dict(self) -> Dict[str, Any]:
        """Generate settings.json"""
        return {
            "BUILDDIR": self.builddir,
            "BUILDCONFIG": self.commonconfig,
        }

    def tasks_to_json_dict(self) -> Dict[str, Any]:
        """Generate tasks.json"""
        # generate outer layer
        build_tasks: Dict[str, Any] = {
            "version": "2.0.0",
            "tasks": []
        }
        # generate inner layer
        tasks = build_tasks["tasks"]
        # add common tasks
        tasks.append({
            "label": "Remove builddir",
            "type": "shell",
            "command": "rm -rf ${config:BUILDDIR}",
        })
        tasks.append({
            "label": "Build",
            "detail": "Run build command",
            "type": "shell",
            "command": "ninja",
            "options": {
                "cwd": "${config:BUILDDIR}"
            },
            "problemMatcher": {
                "base": "$gcc",
                "fileLocation": ["relative", "${config:BUILDDIR}"]
            },
            "group": "build"
        })
        # now, add generated tasks
        tasks.extend([task.to_json_dict() for task in self.build_tasks])

        # we're done
        return build_tasks

    def launch_to_json_dict(self) -> Dict[str, Any]:
        """Generate launch.json"""
        return {
            "version": "0.2.0",
            "configurations": [task.to_json_dict() for task in self.launch_tasks]
        }

    def c_cpp_properties_to_json_dict(self) -> Dict[str, Any]:
        """Generate c_cpp_properties.json"""
        return {
            "configurations": [
                {
                    "name": "Linux",
                    "includePath": [
                        "${config:BUILDDIR}/",
                        "${workspaceFolder}/lib/eal/x86",
                        "${workspaceFolder}/lib/eal/linux",
                        "${workspaceFolder}/**"
                    ],
                    "compilerPath": "/usr/bin/gcc",
                    "cStandard": "c99",
                    "cppStandard": "c++17",
                    "intelliSenseMode": "${default}",
                    "compileCommands": "${config:BUILDDIR}/compile_commands.json"
                }
            ],
            "version": 4
        }


def _whiptail_checklist(prompt: str, labels: List[str],
                        descriptions: List[str],
                        checked: List[bool]) -> List[str]:
    """Display a checklist and get user input."""
    # build whiptail checklist
    checklist = [
        (label, desc, "on" if checked[i] else "off")
        for i, (label, desc) in enumerate(zip(labels, descriptions))
    ]
    # flatten the list
    checklist = [item for sublist in checklist for item in sublist]
    # build whiptail arguments
    args = [
        "whiptail", "--separate-output", "--checklist",
        prompt, "15", "80", "10"
    ] + checklist

    try:
        result = run(args, stderr=PIPE, check=True)
    except CalledProcessError:
        # user probably pressed cancel, so bail out
        _exit(1)
    # capture selected options
    selected = result.stderr.decode().strip().split()
    return selected


def _whiptail_inputbox(prompt: str, default: str = "") -> str:
    """Display an input box and get user input."""
    args = [
        "whiptail", "--inputbox",
        prompt, "10", "70", default
    ]
    result = run(args, stderr=PIPE, check=True)
    return result.stderr.decode().strip()


def _get_enabled_configurations(configs: List[Tuple[str, str, str]],
                                enabled: List[Tuple[str, str, str]]) \
        -> List[Tuple[str, str, str]]:
    """Ask user which build configurations they want."""
    stop = False
    while not stop:
        labels = [task[0] for task in configs]
        descriptions = [task[1] for task in configs]
        checked = [c in enabled for c in configs]
        # when interacting using UI, allow user to specify one custom meson
        # item
        labels += ["add"]
        descriptions += ["Add new option"]
        checked += [False]

        # ask user to select options
        selected = _whiptail_checklist("Select build configurations to enable:",
                                       labels, descriptions, checked)

        # enable all previously existing selected configs
        enabled.clear()
        for task in configs:
            if task[0] in selected:
                # enable this task
                enabled.append(task)
        # if user selected "add", ask for custom meson configuration
        if "add" in selected:
            custom_label = _whiptail_inputbox(
                "Enter custom meson configuration label:")
            custom_description = _whiptail_inputbox(
                "Enter custom meson configuration description:")
            custom_mesonstr = _whiptail_inputbox(
                "Enter custom meson configuration string:")
            new_task = (custom_label, custom_description, custom_mesonstr)
            configs += [new_task]
            # enable the new configuration
            enabled += [new_task]
        else:
            stop = True
    # return our list of enabled configurations
    return enabled


def _get_enabled_list(apps: List[str], enabled: List[str]) -> List[str]:
    """Display a list of items, optionally some enabled by default."""
    checked = [app in enabled for app in apps]

    # ask user to select options
    selected = _whiptail_checklist("Select apps to enable:",
                                   apps, ["" for _ in apps], checked)

    return selected


def _extract_var(path: str, var: str) -> Any:
    """Extract a variable from a meson.build file."""
    try:
        # we don't want to deal with multiline variable assignments
        # so just read entire file in one go
        with open(path, 'r', encoding='utf-8') as file:
            content = file.read()
        parser = mparser.Parser(content, path)
        ast = parser.parse()

        for node in ast.lines:
            # we're only interested in variable assignments
            if not isinstance(node, mparser.AssignmentNode):
                continue
            # we're only interested in the variable we're looking for
            if node.var_name.value != var:
                continue
            # we're expecting string or array
            if isinstance(node.value, mparser.StringNode):
                return node.value.value
            if isinstance(node.value, mparser.ArrayNode):
                return [item.value for item in node.value.args.arguments]
    except (MesonException, FileNotFoundError):
        return []
    return None


def _update_ctx_from_ui(ctx: CmdlineCtx) -> int:
    """Use whiptail dialogs to update context contents."""
    try:
        # update build dir
        ctx.build_dir = _whiptail_inputbox(
            "Enter build directory:", ctx.build_dir)

        # update configs
        ctx.enabled_configs = _get_enabled_configurations(
            ctx.avail_configs, ctx.enabled_configs)

        # update enabled apps, examples, and drivers
        ctx.enabled_apps = _get_enabled_list(ctx.avail_apps, ctx.enabled_apps)
        ctx.enabled_examples = _get_enabled_list(
            ctx.avail_examples, ctx.enabled_examples)
        ctx.enabled_drivers = _get_enabled_list(
            ctx.avail_drivers, ctx.enabled_drivers)

        return 0
    except CalledProcessError:
        # use probably pressed cancel, so bail out
        return 1


def _build_configs(ctx: CmdlineCtx) -> None:
    # if builddir is a relative path, make it absolute from DPDK root
    if not os.path.isabs(ctx.build_dir):
        ctx.build_dir = os.path.realpath(
            os.path.join(ctx.dpdk_dir, ctx.build_dir))

    # first, build our common meson param string
    common_param = ""
    # if no apps enabled, disable all apps, otherwise they get built by default
    if not ctx.enabled_apps:
        common_param += " -Ddisable_apps=*"
    else:
        common_param += f" -Denable_apps={','.join(ctx.enabled_apps)}"
    # examples don't get build unless user asks
    if ctx.enabled_examples:
        common_param += f" -Dexamples={','.join(ctx.enabled_examples)}"
    # if no drivers enabled, disable all drivers, otherwise they get built by
    # default
    if not ctx.enabled_drivers:
        common_param += " -Ddisable_drivers=*/*"
    else:
        common_param += f" -Denable_drivers={','.join(ctx.enabled_drivers)}"

    # create build tasks
    build_tasks = [DPDKBuildTask(l, d, m) for l, d, m in ctx.enabled_configs]

    # create launch tasks
    launch_tasks: List[DPDKLaunchTask] = []
    for app in ctx.enabled_apps:
        label = app
        exe = os.path.join("app", f"dpdk-{app}")
        launch_tasks.append(DPDKLaunchTask(label, exe, ctx.gdb_path))
    for app in ctx.enabled_examples:
        # examples may have complex paths but they always flatten
        label = os.path.basename(app)
        exe = os.path.join("examples", f"dpdk-{label}")
        launch_tasks.append(DPDKLaunchTask(label, exe, ctx.gdb_path))

    # build our config
    vscode_cfg = VSCodeConfig(ctx.build_dir, common_param)
    vscode_cfg.build_tasks = build_tasks
    vscode_cfg.launch_tasks = launch_tasks

    # we're done! now, create .vscode directory
    os.makedirs(os.path.join(ctx.dpdk_dir, ".vscode"), exist_ok=True)

    # ...and create VSCode configuration
    print("Creating VSCode configuration files...")
    config_root = os.path.join(ctx.dpdk_dir, ".vscode")
    func_map = {
        "settings.json": vscode_cfg.settings_to_json_dict,
        "tasks.json": vscode_cfg.tasks_to_json_dict,
        "launch.json": vscode_cfg.launch_to_json_dict,
        "c_cpp_properties.json": vscode_cfg.c_cpp_properties_to_json_dict
    }
    for filename, func in func_map.items():
        with open(os.path.join(config_root, filename), "w", encoding="utf-8") as f:
            print(f"Writing {filename}...")
            f.write(json.dumps(func(), indent=4))
    print("Done!")


def _process_ctx(ctx: CmdlineCtx) -> None:
    """Map command-line enabled options to available options."""
    # for each enabled app, see if it's a wildcard and if so, do a wildcard
    # match
    for app in ctx.enabled_apps[:]:
        if "*" in app:
            ctx.enabled_apps.remove(app)
            ctx.enabled_apps.extend(fnmatch.filter(ctx.avail_apps, app))
    # do the same with examples
    for example in ctx.enabled_examples[:]:
        if "*" in example:
            ctx.enabled_examples.remove(example)
            ctx.enabled_examples.extend(
                fnmatch.filter(ctx.avail_examples, example))
    # do the same with drivers
    for driver in ctx.enabled_drivers[:]:
        if "*" in driver:
            ctx.enabled_drivers.remove(driver)
            ctx.enabled_drivers.extend(
                fnmatch.filter(ctx.avail_drivers, driver))

    # due to wildcard, there may be dupes, so sort(set()) everything
    ctx.enabled_apps = sorted(set(ctx.enabled_apps))
    ctx.enabled_examples = sorted(set(ctx.enabled_examples))
    ctx.enabled_drivers = sorted(set(ctx.enabled_drivers))


def _resolve_deps(ctx: CmdlineCtx) -> None:
    """Resolve driver dependencies."""
    for driver in ctx.enabled_drivers[:]:
        ctx.enabled_drivers.extend(ctx.driver_dep_map.get(driver, []))
    ctx.enabled_drivers = sorted(set(ctx.enabled_drivers))


def _discover_ctx(ctx: CmdlineCtx) -> int:
    """Discover available apps/drivers etc. from DPDK."""
    # find out where DPDK root is located
    _self = os.path.realpath(__file__)
    dpdk_root = os.path.realpath(os.path.join(os.path.dirname(_self), ".."))
    ctx.dpdk_dir = dpdk_root

    # find gdb path
    if ctx.use_gdbsudo:
        gdb = "gdbsudo"
    else:
        gdb = "gdb"
    ctx.gdb_path = shutil.which(gdb)
    if not ctx.gdb_path:
        print(f"Error: Cannot find {gdb} in PATH!", file=stderr)
        return 1

    # we want to extract information from DPDK build files, but we don't have a
    # good way of doing it without already having a meson build directory. for
    # some things we can use meson AST parsing to extract this information, but
    # for drivers extracting this information is not straightforward because
    # they have complex build-time logic to determine which drivers need to be
    # built (e.g. qat). so, we'll use meson AST for apps and examples, but for
    # drivers we'll do it the old-fashioned way: by globbing directories.

    apps: List[str] = []
    examples: List[str] = []
    drivers: List[str] = []

    app_root = os.path.join(dpdk_root, "app")
    examples_root = os.path.join(dpdk_root, "examples")
    drivers_root = os.path.join(dpdk_root, "drivers")

    apps = _extract_var(os.path.join(app_root, "meson.build"), "apps")
    # special case for apps: test isn't added by default
    apps.append("test")
    # some apps will have overridden names using 'name' variable, extract it
    for i, app in enumerate(apps[:]):
        new_name = _extract_var(os.path.join(
            app_root, app, "meson.build"), "name")
        if new_name:
            apps[i] = new_name

    # examples don't have any special cases
    examples = _extract_var(os.path.join(
        examples_root, "meson.build"), "all_examples")

    for root, _, _ in os.walk(drivers_root):
        # some directories are drivers, while some are there simply to
        # organize source in a certain way (e.g. base drivers), so we're
        # going to cheat a little and only consider directories that have
        # exactly two levels (e.g. net/ixgbe) and no others.
        if root == drivers_root:
            continue
        rel_root = os.path.relpath(root, drivers_root)
        if len(rel_root.split(os.sep)) != 2:
            continue
        category = os.path.dirname(rel_root)
        # see if there's a name override
        name = os.path.basename(rel_root)
        new_name = _extract_var(os.path.join(root, "meson.build"), "name")
        if new_name:
            name = new_name
        driver_name = os.path.join(category, name)
        drivers.append(driver_name)

        # some drivers depend on other drivers, so parse these dependencies
        # using the "deps" variable
        deps: List[str] = _extract_var(
            os.path.join(root, "meson.build"), "deps")
        if not deps:
            continue
        for dep in deps:
            # by convention, drivers are named as <category>_<name>, so we can
            # infer that dependency is a driver if it has an underscore
            if not "_" in dep:
                continue
            dep_driver = dep.replace("_", "/")
            ctx.driver_dep_map.setdefault(driver_name, []).append(dep_driver)

    # sort all lists alphabetically
    apps.sort()
    examples.sort()
    drivers.sort()

    # save all of this information into our context
    ctx.avail_apps = apps
    ctx.avail_examples = examples
    ctx.avail_drivers = drivers

    return 0


def _main() -> int:
    """Parse command line arguments and direct program flow."""
    # this is primarily a TUI script, but we also want to be able to automate
    # everything, or set defaults to enhance user interaction and
    # customization.

    # valid parameters:
    # --no-ui: run without any user interaction
    # --no-gdbsudo: set up launch targets to use gdb directly
    # --no-defaults: do not add default build configurations
    # --help: show help message
    # -B/--build-dir: set build directory
    # -b/--build-configs: set default build configurations
    #                     format: <label> <description> <meson-param>
    #                     can be specified multiple times
    # -a/--apps: comma-separated list of enabled apps
    # -e/--examples: comma-separated list of enabled examples
    # -d/--drivers: comma-separated list of enabled drivers
    ap = argparse.ArgumentParser(
        description="Generate VSCode configuration for DPDK")
    ap.add_argument("--no-ui", action="store_true",
                    help="Run without any user interaction")
    ap.add_argument("--no-gdbsudo", action="store_true",
                    help="Set up launch targets to use gdb directly")
    ap.add_argument("--no-defaults", action="store_true",
                    help="Do not enable built-in build configurations")
    ap.add_argument("-B", "--build-dir", default="build",
                    help="Set build directory")
    ap.add_argument("-b", "--build-config", action="append", default=[],
                    help="Comma-separated build task configuration of format [label,description,meson setup arguments]")
    ap.add_argument("-a", "--apps", default="",
                    help="Comma-separated list of enabled apps (wildcards accepted)")
    ap.add_argument("-e", "--examples", default="",
                    help="Comma-separated list of enabled examples (wildcards accepted)")
    ap.add_argument("-d", "--drivers", default="",
                    help="Comma-separated list of enabled drivers (wildcards accepted)")
    ap.epilog = """\
When script is run in interactive mode, parameters will be used to set up dialog defaults. \
Otherwise, they will be used to create configuration directly."""
    args = ap.parse_args()

    def_configs = [
        ("debug", "Debug build", "--buildtype=debug"),
        ("debugopt", "Debug optimized build", "--buildtype=debugoptimized"),
        ("release", "Release build", "--buildtype=release -Denable_docs=true"),
        ("asan", "Address sanitizer build",
         "--buildtype=debugoptimized -Db_sanitize=address -Db_lundef=false"),
    ]
    def_apps = [
        "test", "testpmd"
    ]
    def_examples = [
        "helloworld"
    ]
    # parse build configs
    arg_configs = []
    for c in args.build_config:
        parts = c.split(",")
        if len(parts) != 3:
            print(
                f"Error: Invalid build configuration format: {c}", file=stderr)
            return 1
        arg_configs.append(tuple(parts))

    # set up command line context. all wildcards will be passed directly to _main, and will be
    # resolved later, when we have a list of things to enable/disable.
    ctx = CmdlineCtx()
    ctx.use_ui = not args.no_ui
    ctx.use_gdbsudo = not args.no_gdbsudo
    ctx.build_dir = args.build_dir
    ctx.enabled_apps = args.apps.split(",") if args.apps else []
    ctx.enabled_examples = args.examples.split(",") if args.examples else []
    ctx.enabled_drivers = args.drivers.split(",") if args.drivers else []
    ctx.enabled_configs = arg_configs
    ctx.avail_configs = def_configs + ctx.enabled_configs

    if not args.no_defaults:
        # enable default configs
        ctx.enabled_configs.extend(def_configs)

        # for apps and examples, we only want to add defaults if
        # user didn't directly specify anything
        if not ctx.enabled_apps:
            ctx.enabled_apps.extend(def_apps)
        if not ctx.enabled_examples:
            ctx.enabled_examples.extend(def_examples)

    # if UI interaction is requested, check if whiptail is installed
    if ctx.use_ui and os.system("which whiptail &> /dev/null") != 0:
        print(
            "whiptail is not installed! Please install it and try again.",
            file=stderr)
        return 1

    # check if gdbsudo is available
    if ctx.use_gdbsudo and os.system("which gdbsudo &> /dev/null") != 0:
        print(
            "Generated configuration will use gdbsudo script to run applications.",
            file=stderr)
        print(
            "If you want to use gdb directly, please run with --no-gdbsudo argument.",
            file=stderr)
        print(
            "Otherwise, run the following snippet in your terminal and try again:",
            file=stderr)
        print("""sudo tee <<EOF /usr/local/bin/gdbsudo &> /dev/null
        #!/usr/bin/bash
        sudo gdb $@
        EOF
        sudo chmod a+x /usr/local/bin/gdbsudo""", file=stderr)
        return 1

    _discover_ctx(ctx)
    _process_ctx(ctx)
    if ctx.use_ui and _update_ctx_from_ui(ctx):
        return 1
    _resolve_deps(ctx)
    _build_configs(ctx)

    return 0


if __name__ == "__main__":
    _exit(_main())

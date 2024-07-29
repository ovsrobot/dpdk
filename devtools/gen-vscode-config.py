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
            # take configuration from settings.json using config: namespace
            "command": f"meson setup ${{config:BUILDCONFIG}} " \
                       f"{self.param} ${{config:BUILDDIR}}",
            "problemMatcher": [],
            "group": "build"
        }


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
            # take configuration from settings.json using config: namespace
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
            "configurations": [task.to_json_dict()
                               for task in self.launch_tasks]
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
                    "compileCommands":
                        "${config:BUILDDIR}/compile_commands.json"
                }
            ],
            "version": 4
        }


class CmdlineCtx:
    """POD class to set up command line parameters"""

    def __init__(self):
        self.use_ui = False
        self.use_gdbsudo = False
        self.force_overwrite = False
        self.build_dir = ""
        self.dpdk_dir = ""
        self.gdb_path = ""

        self.avail_configs: List[Tuple[str, str, str]] = []
        self.avail_apps: List[str] = []
        self.avail_examples: List[str] = []
        self.avail_drivers: List[str] = []

        self.enabled_configs_str = ""
        self.enabled_apps_str = ""
        self.enabled_examples_str = ""
        self.enabled_drivers_str = ""
        self.enabled_configs: List[Tuple[str, str, str]] = []
        self.enabled_apps: List[str] = []
        self.enabled_examples: List[str] = []
        self.enabled_drivers: List[str] = []

        self.driver_dep_map: Dict[str, List[str]] = {}
        self.common_conf = ""

        # this is only used by TUI to decide which windows to show
        self.show_apps = False
        self.show_examples = False
        self.show_drivers = False
        self.show_configs = False
        self.show_common_config = False


def _whiptail_msgbox(message: str) -> None:
    """Display a message box."""
    args = ["whiptail", "--msgbox", message, "10", "70"]
    run(args, check=True)


def _whiptail_checklist(title: str, prompt: str,
                        options: List[Tuple[str, str]],
                        checked: List[str]) -> List[str]:
    """Display a checklist and get user input."""
    # build whiptail checklist
    checklist = [
        (label, desc, "on" if label in checked else "off")
        for label, desc in options
    ]
    # flatten the list
    flat = [item for sublist in checklist for item in sublist]
    # build whiptail arguments
    args = [
        "whiptail", "--separate-output", "--checklist",
        "--title", title, prompt, "15", "80", "8"
    ] + flat

    result = run(args, stderr=PIPE, check=True)
    # capture selected options
    return result.stderr.decode().strip().split()


def _whiptail_inputbox(title: str, prompt: str, default: str = "") -> str:
    """Display an input box and get user input."""
    args = [
        "whiptail", "--inputbox",
        "--title", title,
        prompt, "10", "70", default
    ]
    result = run(args, stderr=PIPE, check=True)
    return result.stderr.decode().strip()


def _get_enabled_configurations(configs: List[Tuple[str, str, str]],
                                checked: List[str]) \
        -> List[Tuple[str, str, str]]:
    """Ask user which build configurations they want."""
    stop = False
    while not stop:
        opts = [
            (c[0], c[1]) for c in configs
        ]
        # when interacting using UI, allow adding items
        opts += [("add", "Add new option")]

        # ask user to select options
        checked = _whiptail_checklist(
            "Build configurations", "Select build configurations to enable:",
            opts, checked)

        # if user selected "add", ask for custom meson configuration
        if "add" in checked:
            # remove "" from checked because it's a special option
            checked.remove("add")
            while True:
                custom_label = _whiptail_inputbox(
                    "Configuration name",
                    "Enter custom meson configuration label:")
                custom_description = _whiptail_inputbox(
                    "Configuration description",
                    "Enter custom meson configuration description:")
                custom_mesonstr = _whiptail_inputbox(
                    "Configuration parameters",
                    "Enter custom meson configuration string:")
                # do we have meaningful label?
                if not custom_label:
                    _whiptail_msgbox("Configuration label cannot be empty!")
                    continue
                # don't allow "add", don't allow duplicates
                existing = [task[0] for task in configs] + ["add"]
                if custom_label in existing:
                    _whiptail_msgbox(
                        f"Label '{custom_label}' is not allowed!")
                    continue
                # we passed all checks, stop
                break
            new_task = (custom_label, custom_description, custom_mesonstr)
            configs += [new_task]
            # enable new configuration
            checked += [custom_label]
        else:
            stop = True
    # return our list of enabled configurations
    return [
        c for c in configs if c[0] in checked
    ]


def _select_from_list(title: str, prompt: str, items: List[str],
                      enabled: List[str]) -> List[str]:
    """Display a list of items, optionally some enabled by default."""
    opts = [
        (item, "") for item in items
    ]
    # ask user to select options
    return _whiptail_checklist(title, prompt, opts, enabled)


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
        return None
    return None


def _pick_ui_options(ctx: CmdlineCtx) -> None:
    """Use whiptail dialogs to decide which setup options to show."""
    opts = [
        ("config", "Select build configurations to enable"),
        ("common", "Customize meson flags"),
        ("apps", "Select apps to enable"),
        ("examples", "Select examples to enable"),
        ("drivers", "Select drivers to enable"),
    ]
    # whether any options are enabled depends on whether user has specified
    # anything on the command-line, but also enable examples by default
    checked_opts = ["examples"]
    if ctx.enabled_configs_str:
        checked_opts.append("config")
    if ctx.enabled_apps_str:
        checked_opts.append("apps")
    if ctx.enabled_drivers_str:
        checked_opts.append("drivers")
    if ctx.common_conf:
        checked_opts.append("common")

    enabled = _whiptail_checklist(
        "Options",
        "Select options to configure (deselecting will pick defaults):",
        opts, checked_opts)
    for opt in enabled:
        if opt == "config":
            ctx.show_configs = True
        elif opt == "common":
            ctx.show_common_config = True
        elif opt == "apps":
            ctx.show_apps = True
        elif opt == "examples":
            ctx.show_examples = True
        elif opt == "drivers":
            ctx.show_drivers = True


def _build_configs(ctx: CmdlineCtx) -> int:
    """Build VSCode configuration files."""
    # if builddir is a relative path, make it absolute
    if not os.path.isabs(ctx.build_dir):
        ctx.build_dir = os.path.realpath(ctx.build_dir)

    # first, build our common meson param string
    force_apps = False
    force_drivers = False
    common_param = ctx.common_conf

    # if no apps are specified, all apps are built, so enable all of them. this
    # isn't ideal because some of them might not be able to run because in
    # actuality they don't get built due to missing dependencies. however, the
    # alternative is to not generate any apps in launch configuration at all,
    # which is worse than having some apps defined in config but not available.
    if ctx.enabled_apps_str:
        common_param += f" -Denable_apps={ctx.enabled_apps_str}"
    else:
        # special case: user might have specified -Dtests or apps flags in
        # common param, so if the user did that, assume user knows what they're
        # doing and don't display any warnings about enabling apps, and don't
        # enable them in launch config and leave it up to the user to handle.
        avoid_opts = ['-Dtests=', '-Denable_apps=', '-Ddisable_apps=']
        if not any(opt in common_param for opt in avoid_opts):
            force_apps = True
            ctx.enabled_apps = ctx.avail_apps

    # examples don't get build unless user asks
    if ctx.enabled_examples_str:
        common_param += f" -Dexamples={ctx.enabled_examples_str}"

    # if no drivers enabled, let user know they will be built anyway
    if ctx.enabled_drivers_str:
        common_param += f" -Denable_drivers={ctx.enabled_drivers_str}"
    else:
        avoid_opts = ['-Denable_drivers=', '-Ddisable_drivers=']
        if not any(opt in common_param for opt in avoid_opts):
            # special case: user might have specified driver flags in common
            # param, so if the user did that, assume user knows what they're
            # doing and don't display any warnings about enabling drivers.
            force_drivers = True

    if force_drivers or force_apps:
        ena: List[str] = []
        dis: List[str] = []
        if force_apps:
            ena += ["apps"]
            dis += ["-Ddisable_apps=*"]
        if force_drivers:
            ena += ["drivers"]
            dis += ["-Ddisable_drivers=*/*"]
        ena_str = " or ".join(ena)
        dis_str = " or ".join(dis)
        msg = f"""\
No {ena_str} are specified in configuration, so all of them will be built. \
To disable {ena_str}, add {dis_str} to common meson flags."""

        _whiptail_msgbox(msg)

    # create build tasks
    build_tasks = [DPDKBuildTask(n, d, p) for n, d, p in ctx.enabled_configs]

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
    config_root = os.path.join(ctx.dpdk_dir, ".vscode")
    os.makedirs(config_root, exist_ok=True)

    # ...and create VSCode configuration
    print("Creating VSCode configuration files...")
    func_map = {
        "settings.json": vscode_cfg.settings_to_json_dict,
        "tasks.json": vscode_cfg.tasks_to_json_dict,
        "launch.json": vscode_cfg.launch_to_json_dict,
        "c_cpp_properties.json": vscode_cfg.c_cpp_properties_to_json_dict
    }
    # check if any of the files exist, and refuse to overwrite them unless
    # --force was specified on the command line
    for filename in func_map.keys():
        fpath = os.path.join(config_root, filename)
        if os.path.exists(fpath) and not ctx.force_overwrite:
            print(f"Error: {filename} already exists! \
                Use --force to overwrite.", file=stderr)
            return 1
    for filename, func in func_map.items():
        with open(os.path.join(config_root, filename),
                  "w", encoding="utf-8") as f:
            print(f"Writing {filename}...")
            f.write(json.dumps(func(), indent=4))
    print("Done!")
    return 0


def _resolve_deps(ctx: CmdlineCtx) -> None:
    """Resolve driver dependencies."""
    # resolving dependencies is not straightforward, because DPDK build system
    # treats wildcards differently from explicitly requested drivers: namely,
    # it will treat wildcard-matched drivers on a best-effort basis, and will
    # skip them if driver's dependencies aren't met without error. contrary to
    # that, when a driver is explicitly requested, it will cause an error if
    # any of its dependencies are unmet.
    #
    # to resolve this, we need to be smarter about how we add dependencies.
    # specifically, when we're dealing with wildcards, we will need to add
    # wildcard dependencies, whereas when we're dealing with explicitly
    # requested drivers, we will add explicit dependencies. for example,
    # requesting net/ice will add common/iavf, but requesting net/*ce will
    # add common/* as a dependency. We will build more that we would've
    # otherwise, but that's an acceptable compromise to enable as many drivers
    # as we can while avoiding build errors due to erroneous wildcard matches.
    new_deps: List[str] = []
    for driver in ctx.enabled_drivers_str.split(","):
        # is this a wildcard?
        if "*" in driver:
            # find all drivers matching this wildcard, figure out which
            # category (bus, common, etc.) of driver they request as
            # dependency, and add a wildcarded match on that category
            wc_matches = fnmatch.filter(ctx.avail_drivers, driver)
            # find all of their dependencies
            deps = [d
                    for dl in wc_matches
                    for d in ctx.driver_dep_map.get(dl, [])]
            categories: List[str] = []
            for d in deps:
                category, _ = d.split("/")
                categories += [category]
            # find all categories we've added
            categories = sorted(set(categories))
            # add them as dependencies
            new_deps += [f"{cat}/*" for cat in categories]
            continue
        # this is a driver, so add its dependencies explicitly
        new_deps += ctx.driver_dep_map.get(driver, [])

    # add them to enabled_drivers_str, this will be resolved later
    if new_deps:
        # this might add some dupes but we don't really care
        ctx.enabled_drivers_str += f',{",".join(new_deps)}'


def _update_ctx_from_ui(ctx: CmdlineCtx) -> int:
    """Use whiptail dialogs to update context contents."""
    try:
        # update build dir
        ctx.build_dir = _whiptail_inputbox(
            "Build directory", "Enter build directory:", ctx.build_dir)

        # first, decide what we are going to set up
        _pick_ui_options(ctx)

        # update configs
        if ctx.show_configs:
            ctx.enabled_configs = _get_enabled_configurations(
                ctx.avail_configs, [c[0] for c in ctx.enabled_configs])

        # update common config
        if ctx.show_common_config:
            ctx.common_conf = _whiptail_inputbox(
                "Meson configuration",
                "Enter common meson configuration flags (if any):",
                ctx.common_conf)

        # when user interaction is requestted, we cannot really keep any values
        # we got from arguments, because if user has changed something in those
        # checklists, any wildcards will become invalid. however, we can do a
        # heuristic: if user didn't *change* anything, we can infer that
        # they're happy with the configuration they have picked, so we will
        # only update meson param strings if the user has changed the
        # configuration from TUI, or if we didn't have any to begin with

        old_enabled_apps = ctx.enabled_apps.copy()
        old_enabled_examples = ctx.enabled_examples.copy()
        old_enabled_drivers = ctx.enabled_drivers.copy()
        if ctx.show_apps:
            ctx.enabled_apps = _select_from_list(
                "Apps", "Select apps to enable:",
                ctx.avail_apps, ctx.enabled_apps)
        if ctx.show_examples:
            ctx.enabled_examples = _select_from_list(
                "Examples", "Select examples to enable:",
                ctx.avail_examples, ctx.enabled_examples)
        if ctx.show_drivers:
            ctx.enabled_drivers = _select_from_list(
                "Drivers", "Select drivers to enable:",
                ctx.avail_drivers, ctx.enabled_drivers)

        # did we change anything, assuming we even had anything at all?
        if not ctx.enabled_apps_str or \
                set(old_enabled_apps) != set(ctx.enabled_apps):
            ctx.enabled_apps_str = ",".join(ctx.enabled_apps)
        if not ctx.enabled_examples_str or \
                set(old_enabled_examples) != set(ctx.enabled_examples):
            ctx.enabled_examples_str = ",".join(ctx.enabled_examples)
        if not ctx.enabled_drivers_str or \
                set(old_enabled_drivers) != set(ctx.enabled_drivers):
            ctx.enabled_drivers_str = ",".join(ctx.enabled_drivers)

        return 0
    except CalledProcessError:
        # use probably pressed cancel, so bail out
        return 1


def _resolve_ctx(ctx: CmdlineCtx) -> int:
    """Map command-line enabled options to available options."""
    # for each enabled app, see if it's a wildcard and if so, do a wildcard
    # match
    for app in ctx.enabled_apps_str.split(","):
        if "*" in app:
            ctx.enabled_apps.extend(fnmatch.filter(ctx.avail_apps, app))
        elif app in ctx.avail_apps:
            ctx.enabled_apps.append(app)
        elif app:
            print(f"Error: Unknown app: {app}", file=stderr)
            return 1

    # do the same with examples
    for example in ctx.enabled_examples_str.split(","):
        if "*" in example:
            ctx.enabled_examples.extend(
                fnmatch.filter(ctx.avail_examples, example))
        elif example in ctx.avail_examples:
            ctx.enabled_examples.append(example)
        elif example:
            print(f"Error: Unknown example: {example}", file=stderr)
            return 1

    # do the same with drivers
    for driver in ctx.enabled_drivers_str.split(","):
        if "*" in driver:
            ctx.enabled_drivers.extend(
                fnmatch.filter(ctx.avail_drivers, driver))
        elif driver in ctx.avail_drivers:
            ctx.enabled_drivers.append(driver)
        elif driver:
            print(f"Error: Unknown driver: {driver}", file=stderr)
            return 1

    # due to wildcard, there may be dupes, so sort(set()) everything
    ctx.enabled_apps = sorted(set(ctx.enabled_apps))
    ctx.enabled_examples = sorted(set(ctx.enabled_examples))
    ctx.enabled_drivers = sorted(set(ctx.enabled_drivers))

    return 0


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
        deps: Any = _extract_var(
            os.path.join(root, "meson.build"), "deps")
        if not deps:
            continue
        # occasionally, deps will be a string, so convert it to a list
        if isinstance(deps, str):
            deps = [deps]
        for dep in deps:
            # by convention, drivers are named as <category>_<name>, so we can
            # infer that dependency is a driver if it has an underscore
            if "_" not in dep:
                continue
            dep_driver = dep.replace("_", "/", 1)
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
    # --gdbsudo: set up launch targets to use gdbsudo
    # --no-defaults: do not enable built-in build configurations
    # --help: show help message
    # -B/--build-dir: set build directory
    # -b/--build-config: set default build configurations
    #                    format: <label>,<description>,<meson-param>
    #                    can be specified multiple times
    # -c/--common-conf: additional configuration common to all build tasks
    # -a/--apps: comma-separated list of enabled apps
    # -e/--examples: comma-separated list of enabled examples
    # -d/--drivers: comma-separated list of enabled drivers
    # -f/--force: overwrite existing configuration
    ap = argparse.ArgumentParser(
        description="Generate VSCode configuration for DPDK")
    ap.add_argument("--no-ui", action="store_true",
                    help="Run without any user interaction")
    gdbgrp = ap.add_mutually_exclusive_group()
    gdbgrp.add_argument("--no-gdbsudo", action="store_true",
                        help="Set up launch targets to use gdb directly")
    gdbgrp.add_argument("--gdbsudo", action="store_true",
                        help="Set up launch targets to use gdbsudo")
    ap.add_argument("--no-defaults", action="store_true",
                    help="Do not enable built-in build configurations")
    ap.add_argument("-B", "--build-dir", default="build",
                    help="Set build directory")
    ap.add_argument("-b", "--build-config", action="append", default=[],
                    help="Comma-separated build task configuration of format \
                        [label,description,meson setup arguments]")
    ap.add_argument("-c", "--common-conf",
                    help="Additional configuration common to all build tasks",
                    default="")
    ap.add_argument("-a", "--apps", default="",
                    help="Comma-separated list of enabled apps \
                        (wildcards accepted)")
    ap.add_argument("-e", "--examples", default="",
                    help="Comma-separated list of enabled examples \
                        (wildcards accepted)")
    ap.add_argument("-d", "--drivers", default="",
                    help="Comma-separated list of enabled drivers \
                        (wildcards accepted)")
    ap.add_argument("-f", "--force", action="store_true",
                    help="Overwrite existing configuration")
    ap.epilog = """\
When script is run in interactive mode, parameters will be \
used to set up dialog defaults. Otherwise, they will be used \
to create configuration directly."""
    args = ap.parse_args()

    def_configs = [
        ("debug", "Debug build", "--buildtype=debug"),
        ("debugopt", "Debug build with optimizations",
         "--buildtype=debugoptimized"),
        ("release", "Release build with documentation",
         "--buildtype=release -Denable_docs=true"),
        ("asan", "Address Sanitizer build",
         "--buildtype=debugoptimized -Db_sanitize=address -Db_lundef=false"),
    ]
    # parse build configs
    arg_configs: List[Tuple[str, str, str]] = []
    for c in args.build_config:
        parts: List[str] = c.split(",")
        if len(parts) != 3:
            print(
                f"Error: Invalid build configuration format: {c}", file=stderr)
            return 1
        arg_configs.append(tuple(parts))

    # set up command line context. all wildcards will be passed directly to
    # _main, and will be resolved later, when we have a list of things to
    # enable/disable.
    ctx = CmdlineCtx()
    ctx.use_ui = not args.no_ui
    ctx.force_overwrite = args.force
    ctx.build_dir = args.build_dir
    ctx.common_conf = args.common_conf
    ctx.enabled_configs_str = args.build_config
    ctx.enabled_apps_str = args.apps
    ctx.enabled_examples_str = args.examples
    ctx.enabled_drivers_str = args.drivers
    ctx.enabled_configs = arg_configs
    ctx.avail_configs = def_configs + ctx.enabled_configs

    # if user has specified gdbsudo argument, use that
    if args.gdbsudo or args.no_gdbsudo:
        ctx.use_gdbsudo = args.gdbsudo or not args.no_gdbsudo
    else:
        # use gdb if we're root
        ctx.use_gdbsudo = os.geteuid() != 0
        print(f"Autodetected gdbsudo usage: {ctx.use_gdbsudo}")

    if not args.no_defaults:
        # enable default configs
        ctx.enabled_configs.extend(def_configs)

    # if UI interaction is requested, check if whiptail is installed
    if ctx.use_ui and os.system("which whiptail &> /dev/null") != 0:
        print("whiptail is not installed! Please install it and try again.",
              file=stderr)
        return 1

    # check if gdbsudo is available
    if ctx.use_gdbsudo and os.system("which gdbsudo &> /dev/null") != 0:
        print("Generated configuration will use \
            gdbsudo script to run applications.", file=stderr)
        print("If you want to use gdb directly, \
            please run with --no-gdbsudo argument.", file=stderr)
        print("Otherwise, run the following snippet \
            in your terminal and try again:", file=stderr)
        print("""\
sudo tee <<EOF /usr/local/bin/gdbsudo &> /dev/null
#!/usr/bin/bash
sudo gdb $@
EOF
sudo chmod a+x /usr/local/bin/gdbsudo
""", file=stderr)
        return 1

    if _discover_ctx(ctx):
        return 1
    if _resolve_ctx(ctx):
        return 1
    if ctx.use_ui and _update_ctx_from_ui(ctx):
        return 1
    _resolve_deps(ctx)
    # resolve again because we might have added some dependencies
    if _resolve_ctx(ctx):
        return 1
    return _build_configs(ctx)


if __name__ == "__main__":
    _exit(_main())

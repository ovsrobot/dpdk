#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

"""
Displays an interactive TUI-based menu for configuring a DPDK build directory.
"""

# This is an interactive script that allows the user to configure a DPDK build directory using a
# text-based user interface (TUI). The script will prompt the user to select various configuration
# options, and will then call `meson setup|configure` to configure the build directory with the
# selected options.
#
# To be more user-friendly, the script will also run `meson setup` into a temporary directory in
# the background, which will generate both the list of available options, and any dependencies
# between them, so whenever the user selects an option, we automatically enable its dependencies.
# This will also allow us to use meson introspection to get list of things we are capable of
# building, and warn the user if they selected something that can't be built.

import argparse
import collections
import fnmatch
import json
import os
import subprocess
import sys
import textwrap
import typing as T
from tempfile import TemporaryDirectory


# some apps have different names in the Meson build system
APP_RENAME_MAP = {
    "testpmd": "test-pmd",
}


# cut off dpdk- prefix
def _unprefix_app(app: str) -> str:
    return app[5:]


def _prefix_app(app: str) -> str:
    return f"dpdk-{app}"


def _slash_driver(driver: str) -> str:
    return driver.replace("/", "_", 1)


def _unslash_driver(driver: str) -> str:
    return driver.replace("_", "/", 1)


def create_meson_build(src_dir: str, build_dir: str) -> subprocess.Popen[bytes]:
    """Create a Meson build directory in the background."""
    # we want all examples
    args = ["meson", "setup", build_dir, "-Dexamples=all"]
    return subprocess.Popen(
        args, cwd=src_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def wrap_text(message: str, cols: int) -> T.Tuple[int, int, str]:
    """Wrap text to N columns and calculate resulting dimensions."""
    wrapped_lines = textwrap.wrap(message.strip(), cols)
    h = len(wrapped_lines)
    w = max(len(line) for line in wrapped_lines)
    return h, w, "\n".join(wrapped_lines)


def calc_opt_width(option: T.Any) -> int:
    """Calculate the width of an option."""
    if isinstance(option, str):
        return len(option)
    return sum(calc_opt_width(opt) for opt in option) + len(option)  # padding


def calc_list_width(options: T.List[T.Any], checkbox: bool) -> int:
    """Calculate the width of a list."""
    pad = 5
    # add 4 for the checkbox
    if checkbox:
        pad += 4
    return max(calc_opt_width(opt) for opt in options) + pad


def whiptail_msgbox(message: str) -> None:
    """Display a message box."""
    # set max width to 60
    h, w, message = wrap_text(message, 60)
    # add some padding
    w += 10
    h += 6
    args = ["whiptail", "--msgbox", message, str(h), str(w)]
    subprocess.run(args, check=True)


def whiptail_checklist(
    title: str, prompt: str, options: T.List[T.Tuple[str, str]], checked: T.List[str]
) -> T.List[str]:
    """Display a checklist and get user input."""
    # at least two free spaces, but no more than 10 in total
    lh = min(len(options) + 2, 10)
    # set max width to 60
    h, w, prompt = wrap_text(prompt, 60)
    # width was set to prompt width, but we need to account for the list
    lw = calc_list_width(options, True)
    # adjust width to account for list width as well
    w = max(w, lw)
    # add some padding and list height
    w += 10
    h += 6 + lh

    # build whiptail checklist
    checklist = [
        (label, desc, "on" if label in checked else "off") for label, desc in options
    ]
    # flatten the list
    flat = [item for tup in checklist for item in tup]
    # build whiptail arguments
    args = [
        "whiptail",
        "--notags",
        "--separate-output",
        "--title",
        title,
        "--checklist",
        prompt,
        str(h),
        str(w),
        str(lh),
    ] + flat

    result = subprocess.run(args, stderr=subprocess.PIPE, check=True)
    # capture selected options
    return result.stderr.decode().strip().split()


def whiptail_menu(title: str, prompt: str, options: T.List[T.Tuple[str, str]]) -> str:
    """Display a menu and get user input."""
    # at least two free spaces, but no more than 10 in total
    lh = min(len(options) + 2, 10)
    # set max width to 60
    h, w, prompt = wrap_text(prompt, 60)
    # width was set to prompt width, but we need to account for the list
    lw = calc_list_width(options, False)
    # adjust width to account for list width as well
    w = max(w, lw)
    # add some padding
    w += 10
    h += 6 + lh
    # flatten the list
    flat = [item for tup in options for item in tup]
    args = [
        "whiptail",
        "--notags",
        "--title",
        title,
        "--menu",
        prompt,
        str(h),
        str(w),
        str(lh),
    ] + flat
    result = subprocess.run(args, stderr=subprocess.PIPE, check=True)
    return result.stderr.decode().strip()


def whiptail_inputbox(title: str, prompt: str, default: str = "") -> str:
    """Display an input box and get user input."""
    # set max width to 60
    h, w, prompt = wrap_text(prompt, 60)
    # add some padding
    w += 10
    h += 6
    args = ["whiptail", "--inputbox", "--title", title, prompt, str(h), str(w), default]
    result = subprocess.run(args, stderr=subprocess.PIPE, check=True)
    return result.stderr.decode().strip()


class DPDKBuildInfo:
    """Encapsulate all information about a DPDK build directory."""

    def __init__(self, build_dir: str) -> None:
        self.build_dir = build_dir
        # components that can be built according to meson's introspection
        self.can_be_built: T.Set[str] = set()
        # components that were read from dependency graph
        self.required_deps: T.Dict[str, T.Set[str]] = {}
        self.optional_deps: T.Dict[str, T.Set[str]] = {}
        # separate component list into libs, drivers, apps, and examples
        self.libs: T.Set[str] = set()
        self.drivers: T.Set[str] = set()
        self.apps: T.Set[str] = set()
        self.examples: T.Set[str] = set()

        # store all meson configuration options
        self.meson_flags: T.Dict[str, T.Any] = {}

        self._parse()

    def _parse_dep_line(self, line: str) -> T.Tuple[str, T.Set[str], str, bool]:
        """Parse digraph line into (component, {dependencies}, type, optional)."""
        # extract attributes first
        first, last = line.index("["), line.rindex("]")
        edge_str, attr_str = line[:first], line[first + 1 : last]
        # key=value, key=value, ...
        attrs = {
            key.strip('" '): value.strip('" ')
            for attr_kv in attr_str.split(",")
            for key, value in [attr_kv.strip().split("=", 1)]
        }
        # check if edge is defined as dotted line, meaning it's optional
        optional = "dotted" in attrs.get("style", "")
        try:
            component_type = attrs["dpdk_componentType"]
        except KeyError as _e:
            raise ValueError(f"Error: missing component type: {line}") from _e

        # now, extract component name and any of its dependencies
        deps: T.Set[str] = set()
        try:
            component, deps_str = edge_str.strip('" ').split("->", 1)
            component = component.strip().strip('" ')
            deps_str = deps_str.strip().strip("{}")
            deps = {d.strip('" ') for d in deps_str.split(",")}
        except ValueError as _e:
            component = edge_str.strip('" ')

        return component, deps, component_type, optional

    def _parse(self) -> None:
        """Parse information from DPDK build directory."""

        # first, read the dep graph
        dep_graph_path = os.path.join(self.build_dir, "deps.dot")
        with open(dep_graph_path, encoding="utf-8") as f:
            for line in f:
                # skip lines that aren't edges
                if line.strip() == "digraph {" or line.strip() == "}":
                    continue

                component, deps, c_type, optional = self._parse_dep_line(line)

                # record component type
                type_to_set = {
                    "lib": self.libs,
                    "drivers": self.drivers,
                    "app": self.apps,
                    "examples": self.examples,
                }
                type_to_set[c_type].add(component)

                # store dependencies
                if optional:
                    self.optional_deps[component] = deps
                else:
                    self.required_deps[component] = deps

        # now, use Meson introspection to read the list of components that can be built
        args = ["meson", "introspect", "--targets"]
        output = subprocess.check_output(args, cwd=self.build_dir, encoding="utf-8")
        # parse output as JSON
        introspected_targets = json.loads(output)

        # we want to filter out certain things from the introspection output
        def _filter_target(target: T.Dict[str, T.Any]) -> bool:
            t_name: str = target["name"]
            t_type: str = target["type"]

            # if target is a library, we only want those that start with "rte_"
            if t_type in ["static library", "shared library"]:
                return t_name.startswith("rte_")

            # if target is an executable, we only want those that start with "dpdk-"
            if t_type == "executable":
                return t_name.startswith("dpdk-")

            return False

        for target in filter(_filter_target, introspected_targets):
            t_name: str = target["name"]
            t_type: str = target["type"]

            # for libraries, cut off rte_ prefix
            if t_type in ["static library", "shared library"]:
                t_name = t_name[4:]

            # there may be duplicate targets because of shared/static libraries
            if t_name in self.can_be_built:
                continue

            self.can_be_built.add(t_name)

        # now, use Meson introspection to read build options and their values
        args = ["meson", "introspect", "--buildoptions"]
        output = subprocess.check_output(args, cwd=self.build_dir, encoding="utf-8")
        # parse output as JSON
        introspected_options = json.loads(output)

        # populate available options values from introspection
        for option in introspected_options:
            name = option["name"]
            value = option["value"]

            self.meson_flags[name] = value


class SetupCtx:
    """POD class to hold context for the setup script."""

    def __init__(self) -> None:
        self.complete_dg: DPDKBuildInfo
        # when reconfiguring existing directory, we want to pick up options from existing
        # directory, but pick up everything else from the big dg
        self.configure_dg: DPDKBuildInfo

        # for delayed creation of dependency graph
        self.tmp_build_dir: str
        self.tmp_build_proc: subprocess.Popen[bytes]

        self.use_ui = False
        self.minimal = False
        self.configure = False
        self.dry_run = False
        self.src_dir = ""
        self.build_dir = ""

        self.parsed_input = False

        # what did user specify on the command-line?
        self.enabled_apps_str = ""
        self.enabled_drivers_str = ""
        self.enabled_examples_str = ""
        self.enabled_libs_str = ""
        self.meson_args_str = ""

        # what did we end up with after parsing user's input?
        self.enabled_apps: T.List[str] = []
        self.enabled_drivers: T.List[str] = []
        self.enabled_examples: T.List[str] = []
        self.enabled_libs: T.List[str] = []

    def _create_meson_option_cmd(
        self,
        meson_option_cmd: str,
        entries: T.Set[str],
        rename_func: T.Optional[T.Callable[[str], str]] = None,
    ) -> str:
        """Create a Meson option command from a set of entries."""
        opt_list = [
            entry if rename_func is None else rename_func(entry)
            for entry in sorted(entries)
        ]
        return f"-D{meson_option_cmd}={','.join(opt_list)}"

    def _resolve_wildcard(
        self,
        components: T.Set[str],
        pattern: str,
        pattern_func: T.Optional[T.Callable[[str], str]] = None,
    ) -> T.Set[str]:
        """Match a pattern against a set of components."""
        if not pattern:
            return set()
        if pattern_func is not None:
            pattern = pattern_func(pattern)
        # if this is not a wildcard, return component explicitly - that's what user requested
        if "*" not in pattern:
            return {pattern}
        # this is a wildcard match, so use wildcard matching
        match = {c for c in components if fnmatch.fnmatch(c, pattern)}
        # filter out anything that isn't buildable
        return match & self.complete_dg.can_be_built

    def _parse_list(
        self,
        dst: T.List[str],
        pattern: str,
        rename_func: T.Optional[T.Callable[[str], str]],
        src_set: T.Set[str],
    ) -> None:
        """Populate list from wildcard matches, optionally with rename on the fly."""
        dst.clear()
        res_lst = [
            entry
            for p in pattern.split(",")
            for entry in self._resolve_wildcard(src_set, p, rename_func)
        ]
        dst.extend(res_lst)

    def parse(self) -> None:
        """Parse user input."""
        # when parsing user input, we expect to see a list of components separated by commas, as
        # well as maybe wildcards. We will expand wildcards into a list of components, but by
        # default we won't enable anything that can't be built even if it matches wildcard. also,
        # component named used by Meson user-facing code and component names used in the backend
        # are not exactly the same. for example, apps and examples will not have "dpdk-" prefixes,
        # while drivers will have underscores instead of slashes. we need to take all of that into
        # account when matching user input to actual components.

        enabled_apps_str = self.enabled_apps_str
        enabled_examples_str = self.enabled_examples_str
        enabled_drivers_str = self.enabled_drivers_str
        enabled_libs_str = self.enabled_libs_str
        if self.configure:
            flags = self.configure_dg.meson_flags
            # on configure, override existing build if user input is specified
            enabled_apps_str = enabled_apps_str or flags["enable_apps"]
            enabled_examples_str = enabled_examples_str or flags["examples"]
            enabled_drivers_str = enabled_drivers_str or flags["enable_drivers"]
            enabled_libs_str = enabled_libs_str or flags["enable_libs"]

        # now, parse specified configuration
        self._parse_list(
            self.enabled_apps,
            enabled_apps_str,
            _prefix_app,
            self.complete_dg.apps,
        )
        self._parse_list(
            self.enabled_examples,
            enabled_examples_str,
            _prefix_app,
            self.complete_dg.examples,
        )
        self._parse_list(
            self.enabled_drivers,
            enabled_drivers_str,
            _slash_driver,
            self.complete_dg.drivers,
        )
        self._parse_list(
            self.enabled_libs, enabled_libs_str, None, self.complete_dg.libs
        )
        self.parsed_input = True

    def create_meson_cmdline(self) -> T.List[str]:
        """Dump all configuration into Meson command-line string."""
        assert self.parsed_input, "parse() must be called before create_meson_cmdline()"

        args: T.List[str] = []
        enabled_apps: T.Set[str] = set()
        enabled_drivers: T.Set[str] = set()
        enabled_examples: T.Set[str] = set()
        enabled_libs: T.Set[str] = set()

        # gather everything
        enabled_apps = set(self.enabled_apps)
        enabled_drivers = set(self.enabled_drivers)
        enabled_examples = set(self.enabled_examples)
        enabled_libs = set(self.enabled_libs)

        enabled_all = enabled_examples | enabled_apps | enabled_drivers | enabled_libs

        # gather all dependencies
        new_deps: T.Set[str] = set()
        for component in enabled_all:
            deps = self.complete_dg.required_deps[component]
            new_deps.add(component)
            # deps do not include complete list, so walk through all dependencies
            dep_stack = collections.deque(deps)
            while dep_stack:
                dc = dep_stack.pop()
                if dc in new_deps:
                    continue
                new_deps.add(dc)

                # get dependencies for this dependency
                deps = self.complete_dg.required_deps[dc]
                # recurse deeper
                dep_stack.extend(deps)

        # extend all lists with new dependencies
        enabled_apps |= new_deps & self.complete_dg.apps
        enabled_drivers |= new_deps & self.complete_dg.drivers
        enabled_examples |= new_deps & self.complete_dg.examples
        enabled_libs |= new_deps & self.complete_dg.libs
        enabled_all |= new_deps

        # check if everything can be built
        diff = enabled_all - self.complete_dg.can_be_built
        if diff:
            print(
                f"Warning: {', '.join(diff)} requested but cannot be built",
                file=sys.stderr,
            )

        # we've resolved all dependencies, time to dump it all out

        if enabled_apps:
            # special case: some apps are renamed
            enabled_apps = {APP_RENAME_MAP.get(app, app) for app in enabled_apps}
            args += [
                self._create_meson_option_cmd(
                    "enable_apps", enabled_apps, _unprefix_app
                )
            ]

        if enabled_examples:
            args += [
                self._create_meson_option_cmd(
                    "examples", enabled_examples, _unprefix_app
                )
            ]

        if enabled_drivers:
            args += [
                self._create_meson_option_cmd(
                    "enable_drivers", enabled_drivers, _slash_driver
                )
            ]

        # if we have specified any other components, enabled_libs will not be empty. however, we
        # only want to specify enabled libs if we want to have a minimal build. so, before only
        # enabling libs we depend on, check if user actually wanted a minimal build.
        if (self.minimal or self.enabled_libs) and enabled_libs:
            args += [self._create_meson_option_cmd("enable_libs", enabled_libs)]

        # if minimal build is enabled and tests are not, disable tests as well
        if self.minimal and "dpdk-test" not in enabled_apps:
            args.append("-Dtests=false")

        # did user specify any extra Meson arguments?
        if self.meson_args_str:
            args += self.meson_args_str.split()

        return args


def select_items(
    title: str,
    prompt: str,
    item_list: T.List[str],
    rename_func: T.Optional[T.Callable[[str], str]],
    checked_list: T.List[str],
) -> None:
    """Select items to enable."""
    # create a dialog selection for items
    options = [
        (app, rename_func(app) if rename_func is not None else app)
        for app in sorted(item_list)
    ]

    try:
        selected = whiptail_checklist(
            title,
            prompt,
            options,
            checked_list,
        )
        checked_list.clear()
        checked_list.extend(selected)
    except subprocess.CalledProcessError:
        # user pressed cancel, don't do anything
        pass


def main_menu(ctx: SetupCtx) -> None:
    """Display main menu."""
    while True:
        options = {
            "apps": "Select applications",
            "examples": "Select examples",
            "drivers": "Select drivers",
            "libs": "Select libraries",
            "meson": "Enter custom Meson options",
            "exit": "Save & exit",
        }
        ret = whiptail_menu(
            "Setup DPDK build directory",
            "Select an option",
            list(options.items()),
        )

        if ret not in ["meson", "exit"]:
            # before we're able to use selection dialogs, we need to parse input
            if not ctx.parsed_input:
                # we need to wait for the background process to finish
                print("Parsing dependency tree, please wait...")
                ctx.tmp_build_proc.wait()
                ctx.complete_dg = DPDKBuildInfo(ctx.tmp_build_dir)
                ctx.parse()

        # selector dialogs are pretty similar
        if ret in ["apps", "examples", "libs", "drivers"]:
            selection_screens: T.Dict[str, T.Any] = {
                "apps": (
                    "Applications",
                    "Select applications to enable:",
                    list(ctx.complete_dg.apps),
                    _unprefix_app,
                    ctx.enabled_apps,
                ),
                "examples": (
                    "Examples",
                    "Select example applications to enable:",
                    list(ctx.complete_dg.examples),
                    _unprefix_app,
                    ctx.enabled_examples,
                ),
                "libs": (
                    "Libraries",
                    "Select libraries to enable:",
                    list(ctx.complete_dg.libs),
                    None,
                    ctx.enabled_libs,
                ),
                "drivers": (
                    "Drivers",
                    "Select drivers to enable:",
                    list(ctx.complete_dg.drivers),
                    _unslash_driver,
                    ctx.enabled_drivers,
                ),
            }
            try:
                t, p, il, rf, el = selection_screens[ret]
                select_items(t, p, il, rf, el)

                # did user select something that cannot be built?
                diff = set(el) - ctx.complete_dg.can_be_built
                if diff:
                    comp_str = ", ".join(diff)
                    whiptail_msgbox(
                        f"Warning: selected component(s) {comp_str} cannot be built."
                    )
            except subprocess.CalledProcessError:
                # user pressed cancel, don't do anything
                pass
        elif ret == "meson":
            try:
                ctx.meson_args_str = whiptail_inputbox(
                    "Custom Meson options",
                    "Enter custom options to pass to Meson setup:",
                    ctx.meson_args_str,
                )
            except subprocess.CalledProcessError:
                # user pressed cancel, don't do anything
                pass
        elif ret == "exit":
            break


def parse_args() -> SetupCtx:
    """Parse command-line arguments and return a context."""
    # find out where we are
    self_path = os.path.abspath(__file__)
    # go one level up to get to DPDK source directory
    src_dir = os.path.dirname(os.path.dirname(self_path))

    parser = argparse.ArgumentParser(description="Configure a DPDK build directory.")
    parser.add_argument(
        "--src-dir", "-S", default=src_dir, help="Path to the DPDK source directory."
    )
    parser.add_argument(
        "--build-dir", "-B", default="build", help="Path to the DPDK build directory."
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Disable the TUI and use command-line arguments directly.",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Try to remove unneeded libraries from build.",
    )
    parser.add_argument(
        "--configure",
        action="store_true",
        help="Reconfigure existing build directory instead of creating new one.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print resulting Meson command-line arguments but do not run Meson.",
    )
    parser.add_argument(
        "--apps",
        "-a",
        default="",
        help="Comma-separated list of apps to enable (wildcards are accepted).",
    )
    parser.add_argument(
        "--drivers",
        "-d",
        default="",
        help="Comma-separated list of drivers to enable (wildcards are accepted).",
    )
    parser.add_argument(
        "--examples",
        "-e",
        default="",
        help="Comma-separated list of examples to enable (wildcards are accepted).",
    )
    parser.add_argument(
        "--libs",
        "-l",
        default="",
        help="Comma-separated list of libraries to enable (wildcards are accepted).",
    )
    parser.add_argument(
        "--meson-args", "-m", default="", help="Extra arguments to pass to Meson setup."
    )
    args = parser.parse_args()

    ctx = SetupCtx()
    ctx.build_dir = args.build_dir
    ctx.src_dir = args.src_dir
    ctx.use_ui = not args.no_ui
    ctx.minimal = args.minimal
    ctx.dry_run = args.dry_run
    ctx.configure = args.configure
    ctx.enabled_apps_str = args.apps
    ctx.enabled_drivers_str = args.drivers
    ctx.enabled_examples_str = args.examples
    ctx.enabled_libs_str = args.libs
    ctx.meson_args_str = args.meson_args

    return ctx


def _run_setup(ctx: SetupCtx) -> int:
    # we want the big graph unconditionally
    ctx.tmp_build_proc = create_meson_build(ctx.src_dir, ctx.tmp_build_dir)

    # we want the small graph only if we're reconfiguring
    if ctx.configure:
        # build directory already created, so we can parse the graph directly
        ctx.configure_dg = DPDKBuildInfo(ctx.build_dir)

    # if we're not using the UI, parse input and exit
    if not ctx.use_ui:
        print("UI is disabled, using command-line arguments directly")
        print("Parsing dependency tree...")
        ctx.tmp_build_proc.wait()
        ctx.complete_dg = DPDKBuildInfo(ctx.tmp_build_dir)
        ctx.parse()
    else:
        # we're using menu-driven UI, so wait until user tells us to exit
        try:
            main_menu(ctx)
        except subprocess.CalledProcessError:
            # user pressed cancel, exit
            print("Operation cancelled")
            return 1

    # user may not have selected anything, so graph may still be unparsed
    if not ctx.parsed_input:
        print("Parsing dependency tree...")
        ctx.tmp_build_proc.wait()
        ctx.complete_dg = DPDKBuildInfo(ctx.tmp_build_dir)
        ctx.parse()

    # run meson
    meson_cmd = ["meson", "setup"] if not ctx.configure else ["meson", "configure"]
    meson_cmdline = ctx.create_meson_cmdline()
    run_args = [*meson_cmd, ctx.build_dir, *meson_cmdline]
    print("The following command will be run:")
    print(*run_args, sep=" ")
    if ctx.dry_run:
        return 0
    runret = subprocess.run(run_args, check=False)
    return runret.returncode


def _main() -> int:
    # parse command-line arguments
    try:
        ctx = parse_args()

        with TemporaryDirectory() as tmp_build_dir:
            ctx.tmp_build_dir = tmp_build_dir
            return _run_setup(ctx)
    # any uncaught CalledProcessError is from graph parser
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_main())

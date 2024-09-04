#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

"""
Displays an interactive TUI-based menu for configuring a DPDK build directory.
"""

# This is an interactive script that allows the user to configure a DPDK build directory using a
# text-based user interface (TUI). The script will prompt the user to select various configuration
# options, and will then call `meson setup` to configure the build directory with the selected
# options.
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


# cut off dpdk- prefix
def _rename_app(app: str) -> str:
    return app[5:]


# replace underscore with slash
def _rename_driver(driver: str) -> str:
    return driver.replace("_", "/", 1)


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


class DepGraph:
    """A dependency graph for Meson options."""

    def __init__(self, src_dir: str):
        self.dst_dir = TemporaryDirectory()
        self.src_dir = src_dir
        # start the meson setup process in the background - user needs to call parse_deps() before
        # this class's data is usable
        self._proc = self._create_dep_tree()
        self._deps_parsed = False
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

    def _create_dep_tree(self) -> subprocess.Popen[bytes]:
        # we want all examples as well
        args = ["meson", "setup", self.dst_dir.name, "-Dexamples=all"]
        return subprocess.Popen(
            args, cwd=self.src_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

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

    def parse_deps(self) -> None:
        """Parse the dependencies generated by meson."""
        if self._deps_parsed:
            return
        self._proc.wait()

        # first, read the dep graph
        dep_graph_path = os.path.join(self.dst_dir.name, "deps.dot")
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
        output = subprocess.check_output(args, cwd=self.dst_dir.name, encoding="utf-8")
        # parse output as JSON
        introspected = json.loads(output)

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

        for target in filter(_filter_target, introspected):
            t_name: str = target["name"]
            t_type: str = target["type"]

            # for libraries, cut off rte_ prefix
            if t_type in ["static library", "shared library"]:
                t_name = t_name[4:]

            # there may be duplicate targets because of shared/static libraries
            if t_name in self.can_be_built:
                continue

            self.can_be_built.add(t_name)

        self._deps_parsed = True


class SetupCtx:
    """POD class to hold context for the setup script."""

    def __init__(self) -> None:
        self.dg: DepGraph
        self.use_ui = False
        self.minimal = False
        self.input_parsed = False
        self.dpdk_dir = ""
        self.build_dir = ""

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

        # some apps have different names in Meson
        self.rename_map = {
            "testpmd": "test-pmd",
        }

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

    def _wildcard_match(
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
        # if this is not a wildcard, return component explicitly
        if "*" not in pattern:
            return {pattern}
        # this is a wildcard match, so use wildcard matching
        match = {c for c in components if fnmatch.fnmatch(c, pattern)}
        # filter out anything that isn't buildable
        return match & self.dg.can_be_built

    def parse_input(self) -> None:
        """Parse user input."""
        if self.input_parsed:
            return
        self.dg.parse_deps()

        # when parsing user input, we expect to see a list of components separated by commas, as
        # well as maybe wildcards. We will expand wildcards into a list of components, but by
        # default we won't enable anything that can't be built even if it matches wildcard. also,
        # component named used by Meson user-facing code and component names used in the backend
        # are not exactly the same. for example, apps and examples will not have "dpdk-" prefixes,
        # while drivers will have underscores instead of slashes. we need to take all of that into
        # account when matching user input to actual components.

        def _app_pattern_func(app: str) -> str:
            return f"dpdk-{app}"

        def _driver_pattern_func(driver: str) -> str:
            return driver.replace("/", "_", 1)

        self.enabled_apps = [
            app
            for pattern in self.enabled_apps_str.split(",")
            for app in self._wildcard_match(self.dg.apps, pattern, _app_pattern_func)
        ]
        self.enabled_examples = [
            example
            for pattern in self.enabled_examples_str.split(",")
            for example in self._wildcard_match(
                self.dg.examples, pattern, _app_pattern_func
            )
        ]
        self.enabled_drivers = [
            driver
            for pattern in self.enabled_drivers_str.split(",")
            for driver in self._wildcard_match(
                self.dg.drivers, pattern, _driver_pattern_func
            )
        ]
        self.enabled_libs = [
            lib
            for pattern in self.enabled_libs_str.split(",")
            for lib in self._wildcard_match(self.dg.libs, pattern)
        ]

        self.input_parsed = True

    def create_meson_cmdline(self) -> T.List[str]:
        """Dump all configuration into Meson command-line string."""
        # ensure input was parsed before we got here
        self.parse_input()

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
            deps = self.dg.required_deps[component]
            new_deps.add(component)
            # deps do not include complete list, so walk through all dependencies
            dep_stack = collections.deque(deps)
            while dep_stack:
                dc = dep_stack.pop()
                if dc in new_deps:
                    continue
                new_deps.add(dc)

                # get dependencies for this dependency
                deps = self.dg.required_deps[dc]
                # recurse deeper
                dep_stack.extend(deps)

        # extend all lists with new dependencies
        enabled_apps |= new_deps & self.dg.apps
        enabled_drivers |= new_deps & self.dg.drivers
        enabled_examples |= new_deps & self.dg.examples
        enabled_libs |= new_deps & self.dg.libs
        enabled_all |= new_deps

        # check if everything can be built
        diff = enabled_all - self.dg.can_be_built
        if diff:
            print(
                f"Warning: {', '.join(diff)} requested but cannot be built",
                file=sys.stderr,
            )

        # we've resolved all dependencies, time to dump it all out

        if enabled_apps:
            # special case: some apps are renamed
            enabled_apps = {self.rename_map.get(app, app) for app in enabled_apps}
            args += [
                self._create_meson_option_cmd("enable_apps", enabled_apps, _rename_app)
            ]

        if enabled_examples:
            args += [
                self._create_meson_option_cmd("examples", enabled_examples, _rename_app)
            ]

        if enabled_drivers:
            args += [
                self._create_meson_option_cmd(
                    "enable_drivers", enabled_drivers, _rename_driver
                )
            ]

        # if we have specified any other components, this will not be empty.
        # however, we only want to specify enabled libs if we want to have a
        # minimal build. so, before only enabling libs we depend on, check if
        # user actually wanted a minimal build.
        if (self.minimal or self.enabled_libs) and enabled_libs:
            args += [self._create_meson_option_cmd("enable_libs", enabled_libs)]

        # did user specify any extra Meson arguments?
        if self.meson_args_str:
            args += self.meson_args_str.split()

        return args


def select_items(
    app_list: T.List[str],
    rename_func: T.Optional[T.Callable[[str], str]],
    checked_list: T.List[str],
) -> None:
    """Select apps to enable."""
    # create a dialog selection for apps
    options = [
        (app, rename_func(app) if rename_func is not None else app)
        for app in sorted(app_list)
    ]

    try:
        selected = whiptail_checklist(
            "DPDK standard applications",
            "Select apps to enable",
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
            "apps": "Enable apps",
            "examples": "Enable examples",
            "libs": "Enable libraries",
            "drivers": "Enable drivers",
            "meson": "Enter custom Meson options",
            "exit": "Save & exit",
        }
        ret = whiptail_menu(
            "Setup DPDK build directory",
            "Select an option",
            list(options.items()),
        )

        if ret in ["apps", "examples", "libs", "drivers"]:
            # before we're able to select apps, we need to parse input
            if not ctx.input_parsed:
                print("Parsing dependency tree, please wait...")
                ctx.parse_input()
            selection_screens: T.Dict[str, T.Any] = {
                "apps": (list(ctx.dg.apps), _rename_app, ctx.enabled_apps),
                "examples": (list(ctx.dg.examples), _rename_app, ctx.enabled_examples),
                "libs": (list(ctx.dg.libs), None, ctx.enabled_libs),
                "drivers": (list(ctx.dg.drivers), _rename_driver, ctx.enabled_drivers),
            }
            try:
                items_list, rename_func, enabled_list = selection_screens[ret]
                select_items(items_list, rename_func, enabled_list)

                # did user select something that cannot be built?
                diff = set(enabled_list) - ctx.dg.can_be_built
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
                    "Enter custom Meson options",
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
    dpdk_dir = os.path.dirname(os.path.dirname(self_path))

    parser = argparse.ArgumentParser(description="Configure a DPDK build directory.")
    parser.add_argument(
        "--dpdk-dir", "-S", default=dpdk_dir, help="Path to the DPDK source directory."
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
    ctx.dpdk_dir = args.dpdk_dir
    ctx.use_ui = not args.no_ui
    ctx.minimal = args.minimal
    ctx.enabled_apps_str = args.apps
    ctx.enabled_drivers_str = args.drivers
    ctx.enabled_examples_str = args.examples
    ctx.enabled_libs_str = args.libs
    ctx.meson_args_str = args.meson_args

    return ctx


def _main() -> int:
    # parse command-line arguments
    ctx = parse_args()

    # did we discover a valid DPDK directory?
    if not os.path.exists(os.path.join(ctx.dpdk_dir, "meson.build")):
        raise FileNotFoundError("DPDK source directory not found.")

    # parse deps in background
    ctx.dg = DepGraph(ctx.dpdk_dir)

    # if we're not using the UI, parse input and exit
    if not ctx.use_ui:
        print("UI is disabled, using command-line arguments directly")
        print("Parsing dependency tree...")
        ctx.parse_input()
    else:
        # we're using menu-driven UI, so wait until user tells us to exit
        try:
            main_menu(ctx)
        except subprocess.CalledProcessError:
            # user pressed cancel, exit
            print("Operation cancelled")
            return 1

    # run meson
    meson_cmdline = ctx.create_meson_cmdline()
    run_args = ["meson", "setup", ctx.build_dir, *meson_cmdline]
    print("Running: ", *run_args, sep=" ")
    runret = subprocess.run(run_args, check=True)
    return runret.returncode


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

"""Utility script to build up a list of dependencies from meson."""

import os
import sys
import argparse
import typing as T


def file_to_list(filename: str) -> T.List[str]:
    """Read file into a list of strings."""
    with open(filename, encoding="utf-8") as f:
        return f.readlines()


def list_to_file(filename: str, lines: T.List[str]):
    """Write a list of strings out to a file."""
    with open(filename, "w", encoding="utf-8") as f:
        f.writelines(lines)


def gen_deps(
    component_type: str,
    optional: bool,
    component: str,
    display_name: T.Optional[str],
    deps: T.List[str],
) -> str:
    """Generate a dependency graph for meson."""
    dep_list_str = '", "'.join(deps)
    deps_str = "" if not deps else f' -> {{ "{dep_list_str}" }}'
    # we define custom attributes for the nodes
    attr_str = f'dpdk_componentType="{component_type}"'
    if optional:
        # we use a dotted line to represent optional dependencies
        attr_str += ',style="dotted"'
    if display_name is not None:
        attr_str += f',dpdk_displayName="{display_name}"'
    return f'"{component}"{deps_str} [{attr_str}]\n'


def _main():
    depsfile = f'{os.environ["MESON_BUILD_ROOT"]}/deps.dot'

    # to reset the deps file on each build, the script is called without any params
    if len(sys.argv) == 1:
        os.remove(depsfile)
        sys.exit(0)

    # we got arguments, parse them
    parser = argparse.ArgumentParser(
        description="Generate a dependency graph for meson."
    )
    # type is required
    parser.add_argument(
        "--type", required=True, help="Type of dependency (lib, examples, etc.)"
    )
    parser.add_argument(
        "--optional", action="store_true", help="Whether the dependency is optional"
    )
    parser.add_argument(
        "--display-name",
        help="Component name as it is used in the build system",
    )
    # component is required
    parser.add_argument("component", help="The component to add to the graph")
    parser.add_argument("deps", nargs="*", help="The dependencies of the component")

    parsed = parser.parse_args()

    try:
        contents = file_to_list(depsfile)
    except FileNotFoundError:
        contents = ["digraph {\n", "}\n"]

    # occasionally, component binary name may be different from what it appears in Meson.
    display_name = parsed.display_name

    c_type = parsed.type
    optional = parsed.optional
    component = parsed.component
    deps = parsed.deps
    contents[-1] = gen_deps(c_type, optional, component, display_name, deps)

    contents.append("}\n")

    list_to_file(depsfile, contents)


if __name__ == "__main__":
    _main()

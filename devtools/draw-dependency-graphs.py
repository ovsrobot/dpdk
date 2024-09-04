#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

import argparse
import collections
import sys
import typing as T

# typedef for dependency data types
Deps = T.Set[str]
DepData = T.Dict[str, T.Dict[str, T.Dict[bool, Deps]]]


def parse_dep_line(line: str) -> T.Tuple[str, Deps, str, bool]:
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


def gen_dep_line(component: str, deps: T.Set[str], optional: bool) -> str:
    """Generate a dependency line for a component."""
    # we use dotted line to represent optional components
    attr_str = ' [style="dotted"]' if optional else ""
    dep_list_str = '", "'.join(deps)
    deps_str = "" if not deps else f' -> {{ "{dep_list_str}" }}'
    return f'    "{component}"{deps_str}{attr_str}\n'


def read_deps_list(lines: T.List[str]) -> DepData:
    """Read a list of dependency lines into a dictionary."""
    deps_data: T.Dict[str, T.Any] = {}
    for ln in lines:
        if ln.startswith("digraph") or ln == "}":
            continue

        component, deps, component_type, optional = parse_dep_line(ln)

        # each component will have two sets of dependencies - required and optional
        c_dict = deps_data.setdefault(component_type, {}).setdefault(component, {})
        c_dict[optional] = deps
    return deps_data


def create_classified_graph(deps_data: DepData) -> T.Iterator[str]:
    """Create a graph of dependencies with components classified by type."""
    yield "digraph dpdk_dependencies {\n  overlap=false\n  model=subset\n"
    for n, deps_t in enumerate(deps_data.items()):
        component_type, component_dict = deps_t
        yield f'  subgraph cluster_{n} {{\n    label = "{component_type}"\n'
        for component, optional_d in component_dict.items():
            for optional, deps in optional_d.items():
                yield gen_dep_line(component, deps, optional)
        yield "  }\n"
    yield "}\n"


def parse_match(line: str, dep_data: DepData) -> T.List[str]:
    """Extract list of components from a category string."""
    # if this is not a compound string, we have very few valid choices
    if "/" not in line:
        # is this a category?
        if line in dep_data:
            return list(dep_data[line].keys())
        # this isn't a category. maybe an app name?
        maybe_app_name = f"dpdk-{line}"
        if maybe_app_name in dep_data["app"]:
            return [maybe_app_name]
        if maybe_app_name in dep_data["examples"]:
            return [maybe_app_name]
        # this isn't an app name either, so just look for component with that name
        for _, component_dict in dep_data.items():
            if line in component_dict:
                return [line]
        # nothing found still. one last try: maybe it's a driver? we have to be careful though
        # because a driver name may not be unique, e.g. common/iavf and net/iavf. so, only pick
        # a driver if we can find exactly one driver that matches.
        found_drivers: T.List[str] = []
        for component in dep_data["drivers"].keys():
            _, drv_name = component.split("_", 1)
            if drv_name == line:
                found_drivers.append(component)
        if len(found_drivers) == 1:
            return found_drivers
        # we failed to find anything, report error
        raise ValueError(f"Error: unknown component: {line}")

    # this is a compound string, so we have to do some matching. we may have two or three levels
    # of hierarchy, as driver/net/ice and net/ice should both be valid.

    # if there are three levels of hierarchy, this must be a driver
    try:
        ctype, drv_class, drv_name = line.split("/", 2)
        component_name = f"{drv_class}_{drv_name}"
        # we want to directly access the dict to trigger KeyError, and not catch them here
        if component_name in dep_data[ctype]:
            return [component_name]
        else:
            raise KeyError(f"Unknown category: {line}")
    except ValueError:
        # not three levels of hierarchy, try two
        pass

    first, second = line.split("/", 1)

    # this could still be a driver, just without the "drivers" prefix
    for component in dep_data["drivers"].keys():
        if component == f"{first}_{second}":
            return [component]
    # could be driver wildcard, e.g. drivers/net
    if first == "drivers":
        drv_match: T.List[str] = [
            drv_name
            for drv_name in dep_data["drivers"]
            if drv_name.startswith(f"{second}_")
        ]
        if drv_match:
            return drv_match
    # may be category + component
    if first in dep_data:
        # go through all components in the category
        if second in dep_data[first]:
            return [second]
        # if it's an app or an example, it may have "dpdk-" in front
        if first in ["app", "examples"]:
            maybe_app_name = f"dpdk-{second}"
            if maybe_app_name in dep_data[first]:
                return [maybe_app_name]
    # and nothing of value was found
    raise ValueError(f"Error: unknown component: {line}")


def filter_deps(dep_data: DepData, criteria: T.List[str]) -> None:
    """Filter dependency data to include only specified components."""
    # this is a two step process: when we get a list of components, we need to
    # go through all of them and note any dependencies they have, and expand the
    # list of components with those dependencies. then we filter.

    # walk the dependency list and include all possible dependencies
    deps_seen: Deps = set()
    deps_stack = collections.deque(criteria)
    while deps_stack:
        component = deps_stack.popleft()
        if component in deps_seen:
            continue
        deps_seen.add(component)
        for component_type, component_dict in dep_data.items():
            try:
                deps = component_dict[component]
            except KeyError:
                # wrong component type
                continue
            for _, dep_list in deps.items():
                deps_stack.extend(dep_list)
    criteria += list(deps_seen)

    # now, "components" has all the dependencies we need to include, so we can filter
    for component_type, component_dict in dep_data.items():
        dep_data[component_type] = {
            component: deps
            for component, deps in component_dict.items()
            if component in criteria
        }


def main():
    parser = argparse.ArgumentParser(
        description="Utility to generate dependency tree graphs for DPDK"
    )
    parser.add_argument(
        "--match",
        type=str,
        help="Output hierarchy for component or category, e.g. net/ice, lib, app, drivers/net, etc.",
    )
    parser.add_argument(
        "input_file",
        type=argparse.FileType("r"),
        help="Path to the deps.dot file from a DPDK build directory",
    )
    parser.add_argument(
        "output_file",
        type=argparse.FileType("w"),
        help="Path to the desired output dot file",
    )
    args = parser.parse_args()

    deps = read_deps_list([ln.strip() for ln in args.input_file.readlines()])
    if args.match:
        try:
            filter_deps(deps, parse_match(args.match, deps))
        except (KeyError, ValueError) as e:
            print(e, file=sys.stderr)
            return
    args.output_file.writelines(create_classified_graph(deps))


if __name__ == "__main__":
    main()

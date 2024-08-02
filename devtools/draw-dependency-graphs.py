#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

import argparse
import ast


driver_classes = [
    "baseband",
    "bus",
    "common",
    "compress",
    "crypto",
    "dma",
    "event",
    "gpu",
    "mempool",
    "ml",
    "net",
    "raw",
    "regex",
    "vdpa",
]


def component_type(name: str):
    if name.startswith("dpdk-"):
        return "app"

    nameparts = name.split("_", 1)
    if len(nameparts) > 1 and nameparts[0] in driver_classes:
        return f"drivers/{nameparts[0]}"

    return "lib"


def read_deps_list(lines: list[str]):
    deps_data = {}
    for ln in lines:
        if ln.startswith("digraph") or ln == "}":
            continue

        if "->" in ln:
            component, deps = [s.strip() for s in ln.split("->")]
            deps = ast.literal_eval(deps)
        else:
            component, deps = ln, {}

        component = component.strip('"')
        comp_class = component_type(component)

        if comp_class not in deps_data.keys():
            deps_data[comp_class] = {}
        deps_data[comp_class][component] = deps
    return deps_data


def create_classified_graph(deps_data: dict[dict[list[str]]]):
    yield ("digraph dpdk_dependencies {\n  overlap=false\n  model=subset\n")
    for n, category in enumerate(deps_data.keys()):
        yield (f'  subgraph cluster_{n} {{\n    label = "{category}"\n')
        for component in deps_data[category].keys():
            yield (
                f'    "{component}" -> {deps_data[category][component]}\n'.replace(
                    "'", '"'
                )
            )
        yield ("  }\n")
    yield ("}\n")


def get_deps_for_component(
    dep_data: dict[dict[list[str]]], component: str, comp_deps: set
):
    categories = dep_data.keys()
    comp_deps.add(component)
    for cat in categories:
        if component in dep_data[cat].keys():
            for dep in dep_data[cat][component]:
                get_deps_for_component(dep_data, dep, comp_deps)


def filter_deps(
    dep_data: dict[dict[list[str]]], component: list[str]
) -> dict[dict[list[str]]]:
    components = set()
    for comp in component:
        get_deps_for_component(dep_data, comp, components)

    retval = {}
    for category in dep_data.keys():
        for comp in dep_data[category].keys():
            if comp in components:
                if category not in retval:
                    retval[category] = {}
                retval[category][comp] = dep_data[category][comp]
    return retval


def main():
    parser = argparse.ArgumentParser(
        description="Utility to generate dependency tree graphs for DPDK"
    )
    parser.add_argument(
        "--component",
        type=str,
        help="Only output hierarchy from specified component down.",
    )
    parser.add_argument(
        "--category",
        type=str,
        help="Output hierarchy for all components in given category, e.g. lib, app, drivers/net, etc.",
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
    if args.component:
        deps = filter_deps(deps, [args.component])
    elif args.category:
        deps = filter_deps(deps, deps[args.category].keys())
    args.output_file.writelines(create_classified_graph(deps))


if __name__ == "__main__":
    main()

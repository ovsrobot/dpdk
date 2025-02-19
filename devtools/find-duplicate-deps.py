#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

"""Identify any superfluous dependencies listed in DPDK deps graph."""

import sys

all_deps = {}


class dep:
    """Holds a component and its dependencies."""

    def __init__(self, name, dep_names):
        """Create and process a component and its deps."""
        self.name = name.strip('" ')
        self.base_deps = [all_deps[dn.strip('" ')] for dn in dep_names]
        self.recursive_deps = []
        for d in self.base_deps:
            self.recursive_deps.extend(d.base_deps)
            self.recursive_deps.extend(d.recursive_deps)
        self.extra_deps = []
        for d in self.base_deps:
            if d in self.recursive_deps:
                self.extra_deps.append(d.name)
        if self.extra_deps:
            print(f'{self.name}: extra deps {self.extra_deps}')

    def dict_add(self, d):
        """Add this object to a dictionary by name."""
        d[self.name] = self


def remove_attrs(ln):
    """Remove attributes from a line."""
    while ln.find("[") != -1:
        start = ln.find("[")
        end = ln.find("]")
        ln = ln[:start] + ln[end + 1 :]
    return ln.strip()


def main(argv):
    """Read the dependency tree from a dot file and process it."""
    if len(argv) != 2:
        print(f'Usage: {argv[0]} <build-directory>/deps.dot', file=sys.stderr)
        sys.exit(1)

    with open(argv[1]) as f:
        for ln in f.readlines():
            ln = remove_attrs(ln.strip())
            if '->' in ln:
                name, deps = ln.split('->')
                deps = deps.strip(' {}')
                dep(name, deps.split(',')).dict_add(all_deps)
            elif ln.startswith('"') and ln.endswith('"'):
                dep(ln.strip('"'), []).dict_add(all_deps)


if __name__ == '__main__':
    main(sys.argv)

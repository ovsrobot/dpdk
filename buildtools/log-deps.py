#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation

"""Utility script to build up a list of dependencies from meson."""

import os
import sys


def file_to_list(filename):
    """Read file into a list of strings."""
    with open(filename) as f:
        return f.readlines()


def list_to_file(filename, lines):
    """Write a list of strings out to a file."""
    with open(filename, 'w') as f:
        f.writelines(lines)


depsfile = f'{os.environ["MESON_BUILD_ROOT"]}/deps.dot'

# to reset the deps file on each build, the script is called without any params
if len(sys.argv) == 1:
    os.remove(depsfile)
    sys.exit(0)

try:
    contents = file_to_list(depsfile)
except FileNotFoundError:
    contents = ['digraph {\n', '}\n']

component = sys.argv[1]
if len(sys.argv) > 2:
    contents[-1] = f'"{component}" -> {{ "{"\", \"".join(sys.argv[2:])}" }}\n'
else:
    contents[-1] = f'"{component}"\n'

contents.append('}\n')

list_to_file(depsfile, contents)

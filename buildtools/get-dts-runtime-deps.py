#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 PANTHEON.tech s.r.o.
#

"""Utilities for DTS dependencies.

The module can be used as an executable script,
which verifies that the running Python version meets the version requirement of DTS.
The script exits with the standard exit codes in this mode (0 is success, 1 is failure).

The module also contains a function, get_missing_imports,
which looks for runtime and doc generation dependencies in the DTS pyproject.toml file
and returns a list of module names used in an import statement that are missing.
"""

import configparser
import importlib.metadata
import importlib.util
import os.path
import platform

from packaging.version import Version

_VERSION_COMPARISON_CHARS = '^<>='
_EXTRA_DEPS = {'invoke': '>=1.3', 'paramiko': '>=2.4'}
_DPDK_ROOT = os.path.dirname(os.path.dirname(__file__))
_DTS_DEP_FILE_PATH = os.path.join(_DPDK_ROOT, 'dts', 'pyproject.toml')


def _get_dependencies(cfg_file_path):
    cfg = configparser.ConfigParser()
    with open(cfg_file_path) as f:
        dts_deps_file_str = f.read()
        dts_deps_file_str = dts_deps_file_str.replace("\n]", "]")
        cfg.read_string(dts_deps_file_str)

    deps_section = cfg['tool.poetry.dependencies']
    return {dep: deps_section[dep].strip('"\'') for dep in deps_section}


def get_missing_imports():
    missing_imports = []
    req_deps = _get_dependencies(_DTS_DEP_FILE_PATH)
    req_deps.pop('python')

    for req_dep, req_ver in (req_deps | _EXTRA_DEPS).items():
        try:
            req_ver = Version(req_ver.strip(_VERSION_COMPARISON_CHARS))
            found_dep_ver = Version(importlib.metadata.version(req_dep))
            if found_dep_ver < req_ver:
                print(
                    f'The version "{found_dep_ver}" of package "{req_dep}" '
                    f'is lower than required "{req_ver}".'
                )
        except importlib.metadata.PackageNotFoundError:
            print(f'Package "{req_dep}" not found.')
            missing_imports.append(req_dep.lower().replace('-', '_'))

    return missing_imports


if __name__ == '__main__':
    python_version = _get_dependencies(_DTS_DEP_FILE_PATH).pop('python')
    if python_version:
        sys_ver = Version(platform.python_version())
        req_ver = Version(python_version.strip(_VERSION_COMPARISON_CHARS))
        if sys_ver < req_ver:
            print(
                f'The available Python version "{sys_ver}" is lower than required "{req_ver}".'
            )
            exit(1)

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Red Hat, Inc.

"""Generate a version map file used by GNU or MSVC linker."""

import re
import sys

scriptname, link_mode, abi_version_file, output, *files = sys.argv

# From rte_export.h
export_exp_sym_regexp = re.compile(r"^RTE_EXPORT_EXPERIMENTAL_SYMBOL\(([^,]+), ([0-9]+.[0-9]+)\)")
export_int_sym_regexp = re.compile(r"^RTE_EXPORT_INTERNAL_SYMBOL\(([^)]+)\)")
export_sym_regexp = re.compile(r"^RTE_EXPORT_SYMBOL\(([^)]+)\)")
# From rte_function_versioning.h
ver_sym_regexp = re.compile(r"^RTE_VERSION_SYMBOL\(([^,]+), [^,]+, ([^,]+),")
ver_exp_sym_regexp = re.compile(r"^RTE_VERSION_EXPERIMENTAL_SYMBOL\([^,]+, ([^,]+),")
default_sym_regexp = re.compile(r"^RTE_DEFAULT_SYMBOL\(([^,]+), [^,]+, ([^,]+),")

with open(abi_version_file) as f:
    abi = 'DPDK_{}'.format(re.match("([0-9]+).[0-9]", f.readline()).group(1))

symbols = {}

for file in files:
    with open(file, encoding="utf-8") as f:
        for ln in f.readlines():
            node = None
            symbol = None
            comment = ''
            if export_exp_sym_regexp.match(ln):
                node = 'EXPERIMENTAL'
                symbol = export_exp_sym_regexp.match(ln).group(1)
                comment = ' # added in {}'.format(export_exp_sym_regexp.match(ln).group(2))
            elif export_int_sym_regexp.match(ln):
                node = 'INTERNAL'
                symbol = export_int_sym_regexp.match(ln).group(1)
            elif export_sym_regexp.match(ln):
                node = abi
                symbol = export_sym_regexp.match(ln).group(1)
            elif ver_sym_regexp.match(ln):
                node = 'DPDK_{}'.format(ver_sym_regexp.match(ln).group(1))
                symbol = ver_sym_regexp.match(ln).group(2)
            elif ver_exp_sym_regexp.match(ln):
                node = 'EXPERIMENTAL'
                symbol = ver_exp_sym_regexp.match(ln).group(1)
            elif default_sym_regexp.match(ln):
                node = 'DPDK_{}'.format(default_sym_regexp.match(ln).group(1))
                symbol = default_sym_regexp.match(ln).group(2)

            if not symbol:
                continue

            if node not in symbols:
                symbols[node] = {}
            symbols[node][symbol] = comment

if link_mode == 'msvc':
    with open(output, "w") as outfile:
        print(f"EXPORTS", file=outfile)
        for key in (abi, 'EXPERIMENTAL', 'INTERNAL'):
            if key not in symbols:
                continue
            for symbol in sorted(symbols[key].keys()):
                print(f"\t{symbol}", file=outfile)
            del symbols[key]
else:
    with open(output, "w") as outfile:
        local_token = False
        for key in (abi, 'EXPERIMENTAL', 'INTERNAL'):
            if key not in symbols:
                continue
            print(f"{key} {{\n\tglobal:\n", file=outfile)
            for symbol in sorted(symbols[key].keys()):
                if link_mode == 'mingw' and symbol.startswith('per_lcore'):
                    prefix = '__emutls_v.'
                else:
                    prefix = ''
                comment = symbols[key][symbol]
                print(f"\t{prefix}{symbol};{comment}", file=outfile)
            if not local_token:
                print("\n\tlocal: *;", file=outfile)
                local_token = True
            print("};", file=outfile)
            del symbols[key]
        for key in sorted(symbols.keys()):
            print(f"{key} {{\n\tglobal:\n", file=outfile)
            for symbol in sorted(symbols[key].keys()):
                if link_mode == 'mingw' and symbol.startswith('per_lcore'):
                    prefix = '__emutls_v.'
                else:
                    prefix = ''
                comment = symbols[key][symbol]
                print(f"\t{prefix}{symbol};{comment}", file=outfile)
            print(f"}} {abi};", file=outfile)
            if not local_token:
                print("\n\tlocal: *;", file=outfile)
                local_token = True
            del symbols[key]
        # No exported symbol, add a catch all
        if not local_token:
            print(f"{abi} {{", file=outfile)
            print("\n\tlocal: *;", file=outfile)
            local_token = True
            print("};", file=outfile)

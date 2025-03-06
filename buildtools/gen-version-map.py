#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Red Hat, Inc.

"""Generate a version map file used by GNU linker."""

import re
import sys

# From meson.build
sym_export_regexp = re.compile(r"^RTE_EXPORT_SYMBOL\(([^,]+)\)$")
# From rte_function_versioning.h
sym_ver_regexp = re.compile(r"^RTE_VERSION_SYMBOL\(([^,]+), [^,]+, ([^,]+),")
sym_default_regexp = re.compile(r"^RTE_DEFAULT_SYMBOL\(([^,]+), [^,]+, ([^,]+),")

with open("../ABI_VERSION") as f:
    abi = re.match("([0-9]+).[0-9]", f.readline()).group(1)

symbols = {}

for file in sys.argv[2:]:
    with open(file, encoding="utf-8") as f:
        for ln in f.readlines():
            node = None
            symbol = None
            if sym_export_regexp.match(ln):
                symbol = sym_export_regexp.match(ln).group(1)
            elif sym_ver_regexp.match(ln):
                node = sym_ver_regexp.match(ln).group(1)
                symbol = sym_ver_regexp.match(ln).group(2)
            elif sym_default_regexp.match(ln):
                node = sym_default_regexp.match(ln).group(1)
                symbol = sym_default_regexp.match(ln).group(2)

            if not symbol:
                continue

            if not node:
                node = abi
            if node not in symbols:
                symbols[node] = []
            symbols[node].append(symbol)

with open(sys.argv[1], "w") as outfile:
    local_token = False
    if abi in symbols:
        outfile.writelines(f"DPDK_{abi} {{\n\tglobal:\n\n")
        for symbol in sorted(symbols[abi]):
            outfile.writelines(f"\t{symbol};\n")
        outfile.writelines("\n")
        if not local_token:
            outfile.writelines("\tlocal: *;\n")
            local_token = True
        outfile.writelines("};\n")
        del symbols[abi]
    for key in sorted(symbols.keys()):
        outfile.writelines(f"DPDK_{key} {{\n\tglobal:\n\n")
        for symbol in sorted(symbols[key]):
            outfile.writelines(f"\t{symbol};\n")
        outfile.writelines("\n")
        if not local_token:
            outfile.writelines("\tlocal: *;\n")
            local_token = True
        outfile.writelines(f"}} DPDK_{abi};\n")
        del symbols[key]

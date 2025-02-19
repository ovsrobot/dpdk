#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

import os
import sys


def is_function_line(ln):
    return ln.startswith('\t') and ln.endswith(';\n') and ":" not in ln and "# WINDOWS_NO_EXPORT" not in ln

# MinGW keeps the original .map file but replaces per_lcore* to __emutls_v.per_lcore*
def create_mingw_map_file(input_map, output_map):
    with open(input_map) as f_in, open(output_map, 'w') as f_out:
        f_out.writelines([lines.replace('per_lcore', '__emutls_v.per_lcore') for lines in f_in.readlines()])

def main(args):
    if not args[1].endswith('version.map') or \
            not args[2].endswith('exports.def') and \
            not args[2].endswith('mingw.map'):
        return 1

    if args[2].endswith('mingw.map'):
        create_mingw_map_file(args[1], args[2])
        return 0

# generate def file from map file.
# This works taking indented lines only which end with a ";" and which don't
# have a colon in them, i.e. the lines defining functions only.
    else:
        input_map = args[1]

        # When an optional map file for Microsoft's linker exists, use it. Function aliases can
        # be used in these optional files. They end up in the exports.def file:
        # EXPORTS
        #     rte_net_crc_set_alg=rte_net_crc_set_alg_v26;
        # More details about the export file syntax accepted by Microsoft's linker can be found
        # here:
        # https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170
        optional_input_map = input_map.removesuffix('.map') + '_ms_linker.map'
        if os.path.exists(optional_input_map):
            input_map = optional_input_map

        with open(input_map) as f_in:
            functions = [ln[:-2] + '\n' for ln in sorted(f_in.readlines())
                         if is_function_line(ln)]
            functions = ["EXPORTS\n"] + functions

    with open(args[2], 'w') as f_out:
        f_out.writelines(functions)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

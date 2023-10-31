#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Stephen Hemminger <stephen@networkplumber.org>

import argparse
import sys
import struct
from tempfile import TemporaryFile
from elftools.elf.elffile import ELFFile


def load_sections(elffile):
    """Get sections of interest from ELF"""
    result = []
    DATA = [("cls_q", "cls_q_insns"), ("l3_l4", "l3_l4_hash_insns")]
    for name, tag in DATA:
        section = elffile.get_section_by_name(name)
        if section:
            insns = struct.iter_unpack('<BBhL', section.data())
            result.append([tag, insns])
    return result


def dump_section(name, insns, out):
    """Dump the array of BPF instructructions"""
    print(f'\nstatic struct bpf_insn {name}[] = {{', file=out)
    for bpf in insns:
        code = bpf[0]
        src = bpf[1] >> 4
        dst = bpf[1] & 0xf
        off = bpf[2]
        imm = bpf[3]
        print(f'\t{{{code:#02x}, {dst:4d}, {src:4d}, {off:8d}, {imm:#010x}}},',
              file=out)
    print('};', file=out)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("input",
                        nargs='+',
                        help="input object file path or '-' for stdin")
    parser.add_argument("output", help="output C file path or '-' for stdout")
    return parser.parse_args()


def open_input(path):
    """Open the input file or stdin"""
    if path == "-":
        temp = TemporaryFile()
        temp.write(sys.stdin.buffer.read())
        return temp
    return open(path, "rb")


def open_output(path):
    """Open the output file or stdout"""
    if path == "-":
        return sys.stdout
    return open(path, "w")


def write_header(output):
    """Write file intro header"""
    print("/* SPDX-License-Identifier: BSD-3-Clause", file=output)
    print(" * Compiled BPF instructions do not edit", file=output)
    print(" */\n", file=output)
    print("#include <tap_bpf.h>", file=output)


def main():
    '''program main function'''
    args = parse_args()

    output = open_output(args.output)
    write_header(output)
    for path in args.input:
        elffile = ELFFile(open_input(path))
        sections = load_sections(elffile)
        for name, insns in sections:
            dump_section(name, insns, output)


if __name__ == "__main__":
    main()

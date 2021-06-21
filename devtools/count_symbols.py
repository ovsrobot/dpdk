#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation
from pathlib import Path
import sys, os
import subprocess
import argparse
import re
import datetime

try:
        from parsley import makeGrammar
except ImportError:
        print('This script uses the package Parsley to parse C Mapfiles.\n'
              'This can be installed with \"pip install parsley".')
        exit()

symbolMapGrammar = r"""

ws = (' ' | '\r' | '\n' | '\t')*

ABI_VER = ({})
DPDK_VER = ('DPDK_' ABI_VER)
ABI_NAME = ('INTERNAL' | 'EXPERIMENTAL' | DPDK_VER)
comment = '#' (~'\n' anything)+ '\n'
symbol = (~(';' | '}}' | '#') anything )+:c ';' -> ''.join(c)
global = 'global:'
local = 'local: *;'
symbols = comment* symbol:s ws comment* -> s

abi = (abi_section+):m -> dict(m)
abi_section = (ws ABI_NAME:e ws '{{' ws global* (~local ws symbols)*:s ws local* ws '}}' ws DPDK_VER* ';' ws) -> (e,s)
"""

#abi_ver = ['21', '20.0.1', '20.0', '20']

def get_abi_versions():
    year = datetime.date.today().year - 2000
    s=" |".join(['\'{}\''.format(i) for i in reversed(range(21, year + 1)) ])
    s = s + ' | \'20.0.1\' | \'20.0\' | \'20\''

    return s

def get_dpdk_releases():
    year = datetime.date.today().year - 2000
    s="|".join("{}".format(i) for i in range(19,year + 1))
    pattern = re.compile('^\"v(' + s + ')\.\d{2}\"$')

    cmd = ['git', 'for-each-ref', '--sort=taggerdate', '--format', '"%(tag)"']
    result = subprocess.run(cmd, \
                            stdout=subprocess.PIPE, \
                            stderr=subprocess.PIPE)
    if result.stderr.startswith(b'fatal'):
        result = None

    tags = result.stdout.decode('utf-8').split('\n')

    # find the non-rcs between now and v19.11
    tags = [ tag.replace('\"','') \
             for tag in reversed(tags) \
             if pattern.match(tag) ][:-3]

    return tags


def get_terminal_rows():
    rows, _ = os.popen('stty size', 'r').read().split()
    return int(rows)

def fix_directory_name(path):
    mapfilepath1 = str(path.parent.name)
    mapfilepath2 = str(path.parents[1])
    mapfilepath = mapfilepath2 + '/librte_' + mapfilepath1

    return mapfilepath

# fix removal of the librte_ from the directory names
def directory_renamed(path, rel):
    mapfilepath = fix_directory_name(path)
    tagfile = '{}:{}/{}'.format(rel, mapfilepath,  path.name)

    result = subprocess.run(['git', 'show', tagfile], \
                            stdout=subprocess.PIPE, \
                            stderr=subprocess.PIPE)
    if result.stderr.startswith(b'fatal'):
        result = None

    return result

# fix renaming of map files
def mapfile_renamed(path, rel):
    newfile = None

    result = subprocess.run(['git', 'ls-tree', \
                             rel, str(path.parent) + '/'], \
                            stdout=subprocess.PIPE, \
                            stderr=subprocess.PIPE)
    dentries = result.stdout.decode('utf-8')
    dentries = dentries.split('\n')

    # filter entries looking for the map file
    dentries = [dentry for dentry in dentries if dentry.endswith('.map')]
    if len(dentries) > 1 or len(dentries) == 0:
        return None

    dparts = dentries[0].split('/')
    newfile = dparts[len(dparts) - 1]

    if(newfile is not None):
        tagfile = '{}:{}/{}'.format(rel, path.parent, newfile)

        result = subprocess.run(['git', 'show', tagfile], \
                                stdout=subprocess.PIPE, \
                                stderr=subprocess.PIPE)
        if result.stderr.startswith(b'fatal'):
            result = None

    else:
        result = None

    return result

# renaming of the map file & renaming of directory
def mapfile_and_directory_renamed(path, rel):
    mapfilepath = Path("{}/{}".format(fix_directory_name(path),path.name))

    return mapfile_renamed(mapfilepath, rel)

fix_strategies = [directory_renamed, \
                  mapfile_renamed, \
                  mapfile_and_directory_renamed]

fmt = col_fmt = ""

def set_terminal_output(dpdk_rel):
    global fmt, col_fmt

    fmt = '{:<50}'
    col_fmt = fmt
    for rel in dpdk_rel:
        fmt += '{:<6}{:<6}'
        col_fmt += '{:<12}'

def set_csv_output(dpdk_rel):
    global fmt, col_fmt

    fmt = '{},'
    col_fmt = fmt
    for rel in dpdk_rel:
        fmt += '{},{},'
        col_fmt += '{},,'

output_formats = { None: set_terminal_output, \
                   'terminal': set_terminal_output, \
                   'csv': set_csv_output }
directories = 'drivers, lib'

def main():
    global fmt, col_fmt, symbolMapGrammar

    parser = argparse.ArgumentParser(description='Count symbols in DPDK Libs')
    parser.add_argument('--format-output', choices=['terminal','csv'], \
                        default='terminal')
    parser.add_argument('--directory', choices=directories,
                        default=directories)
    args = parser.parse_args()

    dpdk_rel = get_dpdk_releases()

    # set the output format
    output_formats[args.format_output](dpdk_rel)

    column_titles = ['mapfile'] + dpdk_rel
    print(col_fmt.format(*column_titles))

    symbolMapGrammar = symbolMapGrammar.format(get_abi_versions())
    MAPParser = makeGrammar(symbolMapGrammar, {})

    terminal_rows = get_terminal_rows()
    row = 0

    for src_dir in args.directory.split(','):
        for path in Path(src_dir).rglob('*.map'):
            csym = [0] * 2
            relsym = [str(path)]

            for rel in dpdk_rel:
                i = csym[0] = csym[1] = 0
                abi_sections = None

                tagfile = '{}:{}'.format(rel,path)
                result = subprocess.run(['git', 'show', tagfile], \
                                        stdout=subprocess.PIPE, \
                                        stderr=subprocess.PIPE)

                if result.stderr.startswith(b'fatal'):
                    result = None

                while(result is None and i < len(fix_strategies)):
                    result = fix_strategies[i](path, rel)
                    i += 1

                if result is not None:
                    mapfile = result.stdout.decode('utf-8')
                    abi_sections = MAPParser(mapfile).abi()

                if abi_sections is not None:
                    # which versions are present, and we care about
                    ignore = ['EXPERIMENTAL','INTERNAL']
                    found_ver = [ver \
                                 for ver in abi_sections \
                                 if ver not in ignore]

                    for ver in found_ver:
                        csym[0] += len(abi_sections[ver])

                    # count experimental symbols
                    if 'EXPERIMENTAL' in abi_sections:
                        csym[1] = len(abi_sections['EXPERIMENTAL'])

                relsym += csym

            print(fmt.format(*relsym))
            row += 1

        if((terminal_rows>0) and ((row % terminal_rows) == 0)):
            print(col_fmt.format(*column_titles))

if __name__ == '__main__':
        main()

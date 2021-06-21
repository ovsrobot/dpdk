#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation
'''Tool to count the number of symbols in each DPDK release'''
from pathlib import Path
import sys
import os
import subprocess
import argparse
import re
import datetime

try:
    from parsley import makeGrammar
except ImportError:
    print('This script uses the package Parsley to parse C Mapfiles.\n'
          'This can be installed with \"pip install parsley".')
    sys.exit()

MAP_GRAMMAR = r"""

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

def get_abi_versions():
    '''Returns a string of possible dpdk abi versions'''

    year = datetime.date.today().year - 2000
    tags = " |".join(['\'{}\''.format(i) \
                     for i in reversed(range(21, year + 1)) ])
    tags  = tags + ' | \'20.0.1\' | \'20.0\' | \'20\''

    return tags

def get_dpdk_releases():
    '''Returns a list of dpdk release tags names  since v19.11'''

    year = datetime.date.today().year - 2000
    year_range = "|".join("{}".format(i) for i in range(19,year + 1))
    pattern = re.compile(r'^\"v(' +  year_range + r')\.\d{2}\"$')

    cmd = ['git', 'for-each-ref', '--sort=taggerdate', '--format', '"%(tag)"']
    try:
        result = subprocess.run(cmd, \
                                stdout=subprocess.PIPE, \
                                stderr=subprocess.PIPE,
                                check=True)
    except subprocess.CalledProcessError:
        print("Failed to interogate git for release tags")
        sys.exit()

    tags = result.stdout.decode('utf-8').split('\n')

    # find the non-rcs between now and v19.11
    tags = [ tag.replace('\"','') \
             for tag in reversed(tags) \
             if pattern.match(tag) ][:-3]

    return tags

def fix_directory_name(path):
    '''Prepend librte to the source directory name'''
    mapfilepath1 = str(path.parent.name)
    mapfilepath2 = str(path.parents[1])
    mapfilepath = mapfilepath2 + '/librte_' + mapfilepath1

    return mapfilepath

def directory_renamed(path, rel):
    '''Fix removal of the librte_ from the directory names'''

    mapfilepath = fix_directory_name(path)
    tagfile = '{}:{}/{}'.format(rel, mapfilepath,  path.name)

    try:
        result = subprocess.run(['git', 'show', tagfile], \
                                stdout=subprocess.PIPE, \
                                stderr=subprocess.PIPE,
                                check=True)
    except subprocess.CalledProcessError:
        result = None

    return result

def mapfile_renamed(path, rel):
    '''Fix renaming of map files'''
    newfile = None

    result = subprocess.run(['git', 'ls-tree', \
                             rel, str(path.parent) + '/'], \
                            stdout=subprocess.PIPE, \
                            stderr=subprocess.PIPE,
                            check=True)
    dentries = result.stdout.decode('utf-8')
    dentries = dentries.split('\n')

    # filter entries looking for the map file
    dentries = [dentry for dentry in dentries if dentry.endswith('.map')]
    if len(dentries) > 1 or len(dentries) == 0:
        return None

    dparts = dentries[0].split('/')
    newfile = dparts[len(dparts) - 1]

    if newfile is not None:
        tagfile = '{}:{}/{}'.format(rel, path.parent, newfile)

        try:
            result = subprocess.run(['git', 'show', tagfile], \
                                    stdout=subprocess.PIPE, \
                                    stderr=subprocess.PIPE,
                                    check=True)
        except subprocess.CalledProcessError:
            result = None

    else:
        result = None

    return result

def mapfile_and_directory_renamed(path, rel):
    '''Fix renaming of the map file & the source directory'''
    mapfilepath = Path("{}/{}".format(fix_directory_name(path),path.name))

    return mapfile_renamed(mapfilepath, rel)

def get_terminal_rows():
    '''Find the number of rows in the terminal'''

    rows, _ = os.popen('stty size', 'r').read().split()
    return int(rows)

class FormatOutput():
    '''Format the output to supported formats'''
    output_fmt = ""
    column_fmt = ""

    def __init__(self, format_output, dpdk_releases):
        self.OUTPUT_FORMATS[format_output](self,dpdk_releases)
        self.column_titles = ['mapfile'] +  dpdk_releases

        self.terminal_rows = get_terminal_rows()
        self.row = 0

    def set_terminal_output(self,dpdk_rel):
        '''Set the output format to Tabbed Seperated Values'''

        self.output_fmt = '{:<50}' + \
            ''.join(['{:<6}{:<6}'] * (len(dpdk_rel)))
        self.column_fmt = '{:50}' + \
            ''.join(['{:<12}'] * (len(dpdk_rel)))

    def set_csv_output(self,dpdk_rel):
        '''Set the output format to Comma Seperated Values'''

        self.output_fmt = '{},' + \
            ','.join(['{},{}'] * (len(dpdk_rel)))
        self.column_fmt = '{},' + \
            ','.join(['{},'] * (len(dpdk_rel)))

    def print_columns(self):
        '''Print column rows with release names'''
        print(self.column_fmt.format(*self.column_titles))
        self.row += 1

    def print_row(self,symbols):
        '''Print row of symbol values'''
        print(self.output_fmt.format(*symbols))
        self.row += 1

        if((self.terminal_rows>0) and ((self.row % self.terminal_rows) == 0)):
            self.print_columns()

    OUTPUT_FORMATS = { None: set_terminal_output, \
                       'terminal': set_terminal_output, \
                       'csv': set_csv_output }

SRC_DIRECTORIES = 'drivers, lib'
IGNORE_SECTIONS = ['EXPERIMENTAL','INTERNAL']
FIX_STRATEGIES = [directory_renamed, \
                  mapfile_renamed, \
                  mapfile_and_directory_renamed]

def count_release_symbols(map_parser, release, mapfile_path):
    '''Count the symbols for a given release and mapfile'''
    csym = [0] * 2
    abi_sections = None

    tagfile = '{}:{}'.format(release,mapfile_path)
    try:
        result = subprocess.run(['git', 'show', tagfile], \
                                stdout=subprocess.PIPE, \
                                stderr=subprocess.PIPE,
                                check=True)
    except subprocess.CalledProcessError:
        result = None

    for fix_strategy in FIX_STRATEGIES:
        if result is not None:
            break
        result = fix_strategy(mapfile_path, release)

    if result is not None:
        mapfile = result.stdout.decode('utf-8')
        abi_sections = map_parser(mapfile).abi()

    if abi_sections is not None:
        # which versions are present, and we care about
        found_ver = [ver \
                     for ver in abi_sections \
                     if ver not in IGNORE_SECTIONS]

        for ver in found_ver:
            csym[0] += len(abi_sections[ver])

        # count experimental symbols
        if 'EXPERIMENTAL' in abi_sections:
            csym[1] = len(abi_sections['EXPERIMENTAL'])

    return csym

def main():
    '''Main entry point'''

    parser = argparse.ArgumentParser(description='Count symbols in DPDK Libs')
    parser.add_argument('--format-output', choices=['terminal','csv'], \
                        default='terminal')
    parser.add_argument('--directory', choices=SRC_DIRECTORIES,
                        default=SRC_DIRECTORIES)
    args = parser.parse_args()

    dpdk_releases = get_dpdk_releases()
    format_output = FormatOutput(args.format_output, dpdk_releases)

    map_grammar = MAP_GRAMMAR.format(get_abi_versions())
    map_parser = makeGrammar(map_grammar, {})

    format_output.print_columns()
    for src_dir in args.directory.split(','):
        for path in Path(src_dir).rglob('*.map'):
            relsym = [str(path)]

            for release in dpdk_releases:
                csym = count_release_symbols(map_parser, release, path)
                relsym += csym

            format_output.print_row(relsym)

if __name__ == '__main__':
    main()

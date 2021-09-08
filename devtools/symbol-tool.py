#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation
# pylint: disable=invalid-name
'''Tool to count or list symbols in each DPDK release'''
from pathlib import Path
import sys
import os
import subprocess
import argparse
from argparse import RawTextHelpFormatter
import re
import datetime
try:
    from parsley import makeGrammar
except ImportError:
    print('This script uses the package Parsley to parse C Mapfiles.\n'
          'This can be installed with \"pip install parsley".')
    sys.exit()

DESCRIPTION = '''
This script tracks the growth of stable and experimental symbols
over releases since v19.11. The script has the ability to
count the added symbols between two dpdk releases, and to
list experimental symbols present in two dpdk releases
(expired symbols), including the name & email of the original contributor.

example usages:

Count symbols added since v19.11
$ {s} count-symbols

Count symbols added since v20.11
$ {s} count-symbols --releases v20.11,v21.05

List experimental symbols present in v20.11 and v21.05
$ {s} list-expired --releases v20.11,v21.05

List experimental symbols in libraries only, present since v19.11
$ {s} list-expired --directory lib
'''

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
"""  # noqa: E501


class EnvironException(Exception):
    '''Subclass exception for Pylint\'s happiness.'''


def get_abi_versions():
    '''Returns a string of possible dpdk abi versions'''

    year = datetime.date.today().year - 2000
    tags = " |".join(['\'{}\''.format(i)
                     for i in reversed(range(21, year + 1))])
    tags = tags + ' | \'20.0.1\' | \'20.0\' | \'20\''

    return tags


def get_dpdk_releases():
    '''Returns a list of dpdk release tags names  since v19.11'''

    year = datetime.date.today().year - 2000
    year_range = "|".join("{}".format(i) for i in range(19, year + 1))
    pattern = re.compile(r'^\"v(' + year_range + r')\.\d{2}\"$')

    cmd = ['git', 'for-each-ref', '--sort=taggerdate', '--format', '"%(tag)"']
    try:
        result = subprocess.run(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=True)
    except subprocess.CalledProcessError:
        print("Failed to interogate git for release tags")
        sys.exit()

    tags = result.stdout.decode('utf-8').split('\n')

    # find the non-rcs between now and v19.11
    tags = [tag.replace('\"', '')
            for tag in reversed(tags)
            if pattern.match(tag)][:-3]

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
        result = subprocess.run(['git', 'show', tagfile],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=True)
    except subprocess.CalledProcessError:
        result = None

    return result


def mapfile_renamed(path, rel):
    '''Fix renaming of the map file'''
    newfile = None

    result = subprocess.run(['git', 'ls-tree',
                             rel, str(path.parent) + '/'],
                            stdout=subprocess.PIPE,
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
            result = subprocess.run(['git', 'show', tagfile],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=True)
        except subprocess.CalledProcessError:
            result = None

    else:
        result = None

    return result


def mapfile_and_directory_renamed(path, rel):
    '''Fix renaming of the map file & the source directory'''
    mapfilepath = Path("{}/{}".format(fix_directory_name(path), path.name))

    return mapfile_renamed(mapfilepath, rel)


FIX_STRATEGIES = [directory_renamed,
                  mapfile_renamed,
                  mapfile_and_directory_renamed]


def get_symbols(map_parser, release, mapfile_path):
    '''Count the symbols for a given release and mapfile'''
    abi_sections = {}

    tagfile = '{}:{}'.format(release, mapfile_path)
    try:
        result = subprocess.run(['git', 'show', tagfile],
                                stdout=subprocess.PIPE,
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

    return abi_sections


def get_terminal_rows():
    '''Find the number of rows in the terminal'''

    try:
        return os.get_terminal_size().lines
    except IOError:
        return 0


class IgnoredSymbols():  # pylint: disable=too-few-public-methods
    '''Symbols which are to be be ignored for some period'''

    SYMBOL_TOOL_IGNORE = 'devtools/symboltool.ignore'
    ignore_regex = []
    __initialized = False

    @staticmethod
    def initialize():
        '''intialize once'''

        if IgnoredSymbols.__initialized:
            return
        IgnoredSymbols.__initialized = True

        if 'DPDK_SYMBOL_TOOL_IGNORE' in os.environ:
            IgnoredSymbols.SYMBOL_TOOL_IGNORE = \
                os.environ['DPDK_SYMBOL_TOOL_IGNORE']

            # if the user specifies an ignore file, we can't find then error.
            if not Path(IgnoredSymbols.SYMBOL_TOOL_IGNORE).is_file():
                raise EnvironException('Cannot locate {}\'s '
                                       'ignore file'.format(__file__))

        # if we cannot find the default ignore file, then continue
        if not Path(IgnoredSymbols.SYMBOL_TOOL_IGNORE).is_file():
            return

        lines = open(Path(IgnoredSymbols.SYMBOL_TOOL_IGNORE)).readlines()
        for line in lines:

            line = line.strip()

            # ignore comments and whitespace
            if line.startswith(';') or len(line) == 0:
                continue

            IgnoredSymbols.ignore_regex.append(re.compile(line))

    def __init__(self):
        self.initialize()

    def check_ignore(self, symbol):
        '''Check symbol against the ignore regexes'''

        for exp in self.ignore_regex:
            if exp.search(symbol) is not None:
                return True

        return False


class SymbolOwner():
    '''Find the symbols original contributors name and email'''
    symbol_regex = {}
    blame_regex = {'name': r'author\s(.*)',
                   'email': r'author-mail\s<(.*)>'}

    def __init__(self, libpath, symbol):
        self.libpath = libpath
        self.symbol = symbol

        # find variable definitions in C files, and functions in headers.
        self.symbol_regex = \
            {'*.c':  r'^(?!extern).*' + self.symbol + '[^()]*;',
             '*.h': r'__rte_experimental(?:.*\n){0,2}.*' + self.symbol}

    def find_symbol_location(self):
        '''Find where the symbol is definited in the source'''
        for key in self.symbol_regex:
            for path in Path(self.libpath).rglob(key):
                file_text = open(path).read()

                # find where the symbol is defined, either preceded by
                # rte_experimental tag (functions)
                # or followed by a ; (variables)

                exp = self.symbol_regex[key]
                pattern = re.compile(exp, re.MULTILINE)
                search = pattern.search(file_text)

                if search is not None:
                    symbol_pos = search.span()[1]
                    symbol_line = file_text.count('\n', 0, symbol_pos) + 1

                    return [str(path), symbol_line]
        return None

    def find_symbol_owner(self):
        '''Find the symbols original contributors name and email'''
        owners = {}
        location = self.find_symbol_location()

        if location is None:
            return None

        line = '-L {},{}'.format(location[1], location[1])
        # git blame -p(orcelain) -L(ine) path
        args = ['-p', line, location[0]]

        try:
            result = subprocess.run(['git', 'blame'] + args,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=True)
        except subprocess.CalledProcessError:
            return None

        blame = result.stdout.decode('utf-8')
        for key in self.blame_regex:
            pattern = re.compile(self.blame_regex[key], re.MULTILINE)
            match = pattern.search(blame)

            owners[key] = match.groups()[0]

        return owners


class SymbolCountOutput():
    '''Format the output to supported formats'''
    output_fmt = ""
    column_fmt = ""

    def __init__(self, format_output, dpdk_releases):
        self.OUTPUT_FORMATS[format_output](self, dpdk_releases)
        self.column_titles = ['mapfile'] + dpdk_releases

        self.terminal_rows = get_terminal_rows()
        self.row = 0

    def set_terminal_output(self, dpdk_rel):
        '''Set the output format to Tabbed Separated Values'''

        self.output_fmt = '{:<50}' + \
            ''.join(['{:<6}{:<6}'] * (len(dpdk_rel)))
        self.column_fmt = '{:50}' + \
            ''.join(['{:<12}'] * (len(dpdk_rel)))

    def set_csv_output(self, dpdk_rel):
        '''Set the output format to Comma Separated Values'''

        self.output_fmt = '{},' + \
            ','.join(['{},{}'] * (len(dpdk_rel)))
        self.column_fmt = '{},' + \
            ','.join(['{},'] * (len(dpdk_rel)))

    def print_columns(self):
        '''Print column rows with release names'''
        print(self.column_fmt.format(*self.column_titles))
        self.row += 1

    def print_row(self, mapfile, symbols):
        '''Print row of symbol values'''
        mapfile = str(mapfile)
        print(self.output_fmt.format(*([mapfile] + symbols)))
        self.row += 1

        if((self.terminal_rows > 0) and
           ((self.row % self.terminal_rows) == 0)):
            self.print_columns()

    OUTPUT_FORMATS = {None: set_terminal_output,
                      'terminal': set_terminal_output,
                      'csv': set_csv_output}


class ListExpiredOutput():
    '''Format the output to supported formats'''
    output_fmt = ""
    column_fmt = ""

    def __init__(self, format_output, dpdk_releases):
        self.terminal = True
        self.OUTPUT_FORMATS[format_output](self, dpdk_releases)
        self.column_titles = ['mapfile'] + \
            ['expired (' + ','.join(dpdk_releases) + ')'] + \
            ['contributor name', 'contributor email']

    def set_terminal_output(self, _):
        '''Set the output format to Tabbed Separated Values'''

        self.output_fmt = '{:<50}{:<50}{:<25}{:<25}'
        self.column_fmt = '{:50}{:50}{:25}{:25}'

    def set_csv_output(self, _):
        '''Set the output format to Comma Separated Values'''

        self.output_fmt = '{},{},{},{}'
        self.column_fmt = '{},{},{},{}'
        self.terminal = False

    def print_columns(self):
        '''Print column rows with release names'''
        print(self.column_fmt.format(*self.column_titles))

    def print_row(self, mapfile, symbols, owner):
        '''Print row of symbol values'''

        for symbol in symbols:
            mapfile = str(mapfile)
            name = owner[symbol]['name'] \
                if owner[symbol] is not None else ''
            email = owner[symbol]['email'] \
                if owner[symbol] is not None else ''

            print(self.output_fmt.format(mapfile, symbol, name, email))
            if self.terminal:
                mapfile = ''

    OUTPUT_FORMATS = {None: set_terminal_output,
                      'terminal': set_terminal_output,
                      'csv': set_csv_output}


class CountSymbolsAction:
    ''' Logic to count symbols added since a give release '''
    IGNORE_SECTIONS = ['EXPERIMENTAL', 'INTERNAL']

    def __init__(self, mapfile_path, mapfile_parser, format_output):
        self.path = mapfile_path
        self.parser = mapfile_parser
        self.format_output = format_output
        self.symbols_count = []

    def add_mapfile(self, release):
        ''' add a version mapfile '''
        symbol_count = experimental_count = 0

        symbols = get_symbols(self.parser, release, self.path)

        # which versions are present, and we care about
        abi_vers = [abi_ver
                    for abi_ver in symbols
                    if abi_ver not in self.IGNORE_SECTIONS]

        for abi_ver in abi_vers:
            symbol_count += len(symbols[abi_ver])

        # count experimental symbols
        if 'EXPERIMENTAL' in symbols.keys():
            experimental_count = len(symbols['EXPERIMENTAL'])

        self.symbols_count += [symbol_count, experimental_count]

    def __del__(self):
        self.format_output.print_row(self.path.parent, self.symbols_count)


class ListExpiredAction:
    ''' Logic to list expired symbols between two releases '''

    def __init__(self, mapfile_path, mapfile_parser, format_output):
        self.path = mapfile_path
        self.parser = mapfile_parser
        self.format_output = format_output
        self.experimental_symbols = []
        self.ignored_symbols = IgnoredSymbols()

    def add_mapfile(self, release):
        ''' add a version mapfile '''
        symbols = get_symbols(self.parser, release, self.path)

        if 'EXPERIMENTAL' in symbols.keys():
            experimental = [exp.strip() for exp in symbols['EXPERIMENTAL']]

            self.experimental_symbols.append(experimental)

    def __del__(self):
        if len(self.experimental_symbols) != 2:
            return

        tmp = self.experimental_symbols
        # find symbols present in both dpdk releases
        intersect_syms = [sym for sym in tmp[0] if sym in tmp[1]]

        # remove ignored symbols
        intersect_syms = [sym for sym in intersect_syms if not
                          self.ignored_symbols.check_ignore(sym)]

        # check for empty set
        if intersect_syms == []:
            return

        sym_owner = {}
        for sym in intersect_syms:
            sym_owner[sym] = \
                SymbolOwner(self.path.parent, sym).find_symbol_owner()

        self.format_output.print_row(self.path.parent,
                                     intersect_syms,
                                     sym_owner)


SRC_DIRECTORIES = 'drivers,lib'

ACTIONS = {None: CountSymbolsAction,
           'count-symbols': CountSymbolsAction,
           'list-expired': ListExpiredAction}

ACTION_OUTPUT = {None: SymbolCountOutput,
                 'count-symbols': SymbolCountOutput,
                 'list-expired': ListExpiredOutput}


def main():
    '''Main entry point'''

    dpdk_releases = get_dpdk_releases()

    parser = \
        argparse.ArgumentParser(description=DESCRIPTION.format(s=__file__),
                                formatter_class=RawTextHelpFormatter)

    parser.add_argument('mode', choices=['count-symbols', 'list-expired'])
    parser.add_argument('--format-output', choices=['terminal', 'csv'],
                        default='terminal')
    parser.add_argument('--directory', choices=SRC_DIRECTORIES.split(','),
                        default=SRC_DIRECTORIES)
    parser.add_argument('--releases',
                        help='2 x comma separated release tags e.g. \''
                        + ','.join([dpdk_releases[0], dpdk_releases[-1]])
                        + '\'')
    args = parser.parse_args()

    if args.releases is not None:
        dpdk_releases = args.releases.split(',')

    if args.mode == 'list-expired':
        if len(dpdk_releases) < 2:
            sys.exit('Please specify two releases to compare '
                     'in \'list-expired\' mode.')
        dpdk_releases = [dpdk_releases[0],
                         dpdk_releases[len(dpdk_releases) - 1]]

    action = ACTIONS[args.mode]
    format_output = ACTION_OUTPUT[args.mode](args.format_output, dpdk_releases)

    map_grammar = MAP_GRAMMAR.format(get_abi_versions())
    map_parser = makeGrammar(map_grammar, {})

    format_output.print_columns()

    for src_dir in args.directory.split(','):
        for path in Path(src_dir).rglob('*.map'):
            release_action = action(path, map_parser, format_output)

            for release in dpdk_releases:
                release_action.add_mapfile(release)

            # all the magic happens in the destructor
            del release_action


if __name__ == '__main__':
    main()

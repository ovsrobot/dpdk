#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Ericsson AB

import sys
import re

def strip_cpp(header):
    no_cpp = ""
    header = header.replace("\\\n", " ")

    for line in header.split("\n"):
        if re.match(r'^\s*#.*', line) is None and len(line) > 0:
            no_cpp += "%s\n" % line

    return no_cpp


def strip_comments(header):
    no_c_comments = re.sub(r'/\*.*?\*/', '', header, flags=re.DOTALL)
    no_cxx_comments = re.sub(r'//.*', '', no_c_comments)
    return no_cxx_comments


def strip(header):
    header = strip_comments(header)
    header = strip_cpp(header)
    return header


def has_extern_c(header):
    return header.find('extern "C"') != -1


def has_vars(header):
    return re.search(r'^extern\s+[a-z0-9_]+\s.*;', header, flags=re.MULTILINE) is not None


FUNCTION_RES = [
    r'rte_[a-z0-9_]+\(',
    r'cmdline_[a-z0-9_]+\(',
    r'vt100_[a-z0-9_]+\(',
    r'rdline_[a-z0-9_]+\(',
    r'cirbuf_[a-z0-9_]+\(',
    # Windows UNIX compatibility
    r'pthread_[a-z0-9_]+\(',
    r'regcomp\(',
    r'count_cpu\('
]


def has_functions(header):
    for function_re in FUNCTION_RES:
        if re.search(function_re, header) is not None:
            return True
    return False


def has_symbols(header):
    return has_functions(header) or has_vars(header)


def chk_missing(filename):
    header = open(filename).read()
    if has_symbols(header) and not has_extern_c(header):
        print(filename)


def chk_redundant(filename):
    header = open(filename).read()
    if not has_symbols(header) and has_extern_c(header):
        print(filename)

if len(sys.argv) < 3:
    print("%s missing|redundant <header-file> ..." % sys.argv[0])
    sys.exit(1)

op = sys.argv[1]
headers = sys.argv[2:]

for header in headers:
    if op == 'missing':
        chk_missing(header)
    elif op == 'redundant':
        chk_redundant(header)
    else:
        print("Unknown operation.")
        sys.exit(1)

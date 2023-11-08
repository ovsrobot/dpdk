#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation
#

import argparse
import sys
import os
from os.path import join
from subprocess import run, PIPE, STDOUT
from packaging.version import Version

parser = argparse.ArgumentParser()
parser.add_argument('sphinx')
parser.add_argument('version')
parser.add_argument('src')
parser.add_argument('dst')
parser.add_argument('--dts-root', default='.')
args, extra_args = parser.parse_known_args()

# set the version in environment for sphinx to pick up
os.environ['DPDK_VERSION'] = args.version
os.environ['DTS_ROOT'] = args.dts_root

# for sphinx version >= 1.7 add parallelism using "-j auto"
ver = run([args.sphinx, '--version'], stdout=PIPE,
          stderr=STDOUT).stdout.decode().split()[-1]
sphinx_cmd = [args.sphinx] + extra_args
if Version(ver) >= Version('1.7'):
    sphinx_cmd += ['-j', 'auto']

# find all the files sphinx will process so we can write them as dependencies
srcfiles = []
for root, dirs, files in os.walk(args.src):
    srcfiles.extend([join(root, f) for f in files])

# run sphinx, putting the html output in a "html" directory
with open(join(args.dst, 'sphinx_html.out'), 'w') as out:
    process = run(
        sphinx_cmd + ['-b', 'html', args.src, join(args.dst, 'html')],
        stdout=out
    )

# create a gcc format .d file giving all the dependencies of this doc build
with open(join(args.dst, '.html.d'), 'w') as d:
    d.write('html: ' + ' '.join(srcfiles) + '\n')

sys.exit(process.returncode)

#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation
#

import argparse
import sys
import os
from os.path import join
from subprocess import run

parser = argparse.ArgumentParser()
parser.add_argument('sphinx')
parser.add_argument('version')
parser.add_argument('src')
parser.add_argument('dst')
args, extra_args = parser.parse_known_args()

# set the version in environment for sphinx to pick up
os.environ['DPDK_VERSION'] = args.version

sphinx_cmd = [args.sphinx] + extra_args

# find all the files sphinx will process so we can write them as dependencies
srcfiles = []
for root, dirs, files in os.walk(args.src):
    srcfiles.extend([join(root, f) for f in files])

if not os.path.exists(args.dst):
    os.makedirs(args.dst)

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

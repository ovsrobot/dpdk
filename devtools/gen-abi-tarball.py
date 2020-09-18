#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

"""
This Python script generates a compressed archive containing .dump
files which can be used to perform ABI breakage checking for the
build specified in the parameters.
"""

import os
from os.path import abspath, realpath, dirname, basename, join, getsize
import sys
import argparse
import platform
import tarfile
import subprocess
import shutil
import tempfile

# Get command line options
def args_parse():
    parser = argparse.ArgumentParser(
            description='This script is intended to generate ABI dump tarballs\n\n'+
                        'Supported environmental variables:\n'+
                        '\t- CC: The required compiler will be determined using this environmental variable.\n',
            formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
            '-t', '--tag', type=str, dest='tag',
            help='DPDK tag e.g. latest or v20.11', default='latest')
    parser.add_argument(
            '-cf', '--cross-file', type=str, dest='crosscompile',
            help='Set the location of a cross compile config')
    parser.add_argument(
            '-a', '--arch', type=str, dest='arch',
            help='Architecture arm or x86_64', default=platform.machine())
    args = parser.parse_args()
    return args

# Function to execute git commands
def call_git(args):
    args = list(filter(None, args))
    git_call = subprocess.run(['git'] + args, capture_output=True)
    if git_call.returncode != 0:
        print('ERROR Git returned an error', file=sys.stderr)
        exit(1)
    return git_call.stdout.decode('utf-8').strip()

# Function to execute commands
def call_exec(args):
    args = list(filter(None, args))
    exec_call = subprocess.run(args, stdout=subprocess.DEVNULL)
    if exec_call.returncode != 0:
        print('ERROR Script returned an error', file=sys.stderr)
        exit(1)

# Get the required git tag
def get_tag(tag):
    tags = call_git(['ls-remote', '--tags', 'http://dpdk.org/git/dpdk']).split('\n')
    tags = [t.split('/')[-1].strip() for t in tags if 'rc' not in t and not t.endswith('{}')]
    if tag == 'latest':
        tag = tags[-1]
    if tag not in tags:
        print('ERROR supplied tag does not exist in DPDK repo', file=sys.stderr)
        exit(1)
    return tag

def main():
    args = args_parse()

    # Get the cross-compile option
    cross_comp_meson = [None, None]
    if args.crosscompile:
        cross_comp_meson = ['--cross-file', abspath(args.crosscompile)]

    tag = get_tag(args.tag)

    # Get the specified compiler from system
    if 'CC' in os.environ:
        comp = os.environ['CC']
    else:
        print('No compiler specified in environmental varibles, setting CC=gcc')
        comp = 'gcc'
        os.environ['CC'] = 'gcc'

    # Print the configuration to the user
    print('\nSelected Build: {}, Compiler: {}, Architecture: {}, Cross Compile: {}'.format(tag,comp,args.arch,cross_comp_meson[1]))

    # Store the users working directory
    baseDir = os.getcwd()
    # Store devtools dir
    devtoolsDir = abspath(dirname(realpath(sys.argv[0])))

    # Create directory for DPDK git repo and build
    tmpDir = tempfile.TemporaryDirectory(dir = "/tmp")

    os.chdir(tmpDir.name)
    # Clone DPDK and switch to specified tag
    print('Cloning {} from DPDK git'.format(tag))
    call_git(['clone', '--quiet', 'http://dpdk.org/git/dpdk'])
    os.chdir('dpdk')
    call_git(['checkout', '--quiet', tag])

    # Create build folder with meson and set debug build and cross compile (if needed)
    print('Configuring Meson')
    call_exec(['meson', '-Dbuildtype=debug', 'dumpbuild'] + cross_comp_meson)
    #os.system('meson -Dbuildtype=debug dumpbuild {} >/dev/null'.format(cross_comp_meson))
    print('Building DPDK . . .')
    #Build DPDK with ninja
    call_exec(['ninja', '-C', 'dumpbuild'])

    # Create dump files and output to dump directory
    dumpDir = join(baseDir,'{}-{}-{}-abi_dump'.format(tag,comp,args.arch))
    print('Generating ABI dump files')
    call_exec([join(devtoolsDir,'gen-abi.sh'), 'dumpbuild'])
    try:
        shutil.copytree('dumpbuild/dump', dumpDir)
    except FileExistsError as error:
        print('ERROR The {} directory already exists, ensure it is not present before running script'.format(dumpDir), file=sys.stderr)
        tmpDir.cleanup()
        exit(1)

    # Compress the dump directory
    print('Creating Tarball of dump files')
    os.chdir(baseDir)
    origSize = 0
    for f in os.scandir(dumpDir):
        origSize += getsize(f)
    with tarfile.open('{}.tar.gz'.format(dumpDir), "w:gz") as tar:
        tar.add(dumpDir, arcname=basename(dumpDir))
    newSize = getsize('{}.tar.gz'.format(dumpDir))

    # Remove all temporary directories
    print('Cleaning up temporary directories')
    shutil.rmtree(dumpDir)
    tmpDir.cleanup()

    #Print output of the script to the user
    print('\nDump of DPDK ABI {} is available in {}.tar.gz (Original Size: {:.1f}MB, Compressed Size: {:.1f}MB)\n'.format(tag,dumpDir.split('/')[-1],float(origSize)*1e-6,float(newSize)*1e-6))

if __name__ == "__main__":
    main()

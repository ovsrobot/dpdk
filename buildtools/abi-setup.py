#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

"""
This script is intended to be invoked by meson to do the required setup
for performing ABI breakage checks at build time.
The required ABI dump archives can come from several sources including
being generated at build time or prebuilt archives can be pulled from a
remote http location or local directory.
"""

import sys
import os
from os.path import abspath, join, exists, isfile
import argparse
import platform
import subprocess
import requests
import tarfile
import shutil

# Get command line options
def args_parse():
    # Get command line arguments
    parser = argparse.ArgumentParser(
            description='This script is intended to setup ABI dumps for meson to perform ABI checks\n'+
                        'Supported environmental variables\n'+
                        '\t- DPDK_ABI_DUMPS_PATH: Can be used to specify a custom directory for the systems dump directories.\n'+
                        '\t- CC: The required compiler will be determined using this environmental variable.\n'+
                        '\t- DPDK_ABI_TAR_URI: Can be used to specify a location that the script can pull prebuilt or cached dump archives from. This can be a remote http location or a local directory.\n',
            formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
            '-t', '--tag', dest='tag', type=str,
            help='DPDK tag e.g. latest or v20.11', default='latest')
    parser.add_argument(
            '-d', '--dpdk', dest='dpdk', type=str,
            help='Path to DPDK source directory', required=True)
    args = parser.parse_args()
    return args

# Function to execute git commands
def call_git(args):
    args = list(filter(None, args))
    git_call = subprocess.run(['git'] + args, capture_output=True)
    if git_call.returncode != 0:
        print('ERROR Git returned an error', file=sys.stderr)
        exit(1)
    return git_call.stdout.decode('utf-8')

# Function to execute commands
def call_exec(args):
    args = list(filter(None, args))
    exec_call = subprocess.run(args, stdout=subprocess.DEVNULL)
    if exec_call.returncode != 0:
        print('ERROR Script returned an error', file=sys.stderr)
        exit(1)

# Get required git tag
def get_tag(tag):
    tags = call_git(['ls-remote', '--tags', 'http://dpdk.org/git/dpdk']).split('\n')
    tags = [t.split('/')[-1].strip() for t in tags if 'rc' not in t and not t.endswith('{}') and t != '']
    if tag == 'latest':
        tag = tags[-1]
    if tag not in tags:
        print('ERROR supplied tag does not exist in DPDK repo', file=sys.stderr)
        exit(1)
    return tag

def main():
    args = args_parse()

    tag = get_tag(args.tag)

    # Get the specified compiler from system
    if 'CC' in os.environ:
        comp = os.environ['CC']
    else:
        comp = 'gcc'

    # Get the systems architecture
    arch = platform.machine()

    # Get devtools path
    devtools_path = abspath(join(args.dpdk,'devtools'))

    # Get the abi dumps folder from args or env fail if none supplied
    abi_folder = ''
    abi_env = 'DPDK_ABI_DUMPS_PATH'
    if abi_env in os.environ:
        abi_folder = abspath(os.environ[abi_env])
    else:
        abi_folder = abspath(join(args.dpdk,'abi_dumps'))

    # If the directory doesn't exist create it and add a README to explain what it does
    if not exists(abi_folder):
        os.makedirs(abi_folder)
        f=open(abi_folder+'/README','w+')
        f.write('This directory has been setup to contain the ABI dump folders needed to perform ABI checks\n')
        f.write('Directories here must be in the format {DPDK Tag}-{Compiler ID}-{Architecture}-abi_dump\n')
        f.write('e.g. v20.11-gcc-x86_64-abi_dump\n')
        f.write('Directories that do not use this format will not be picked up by the meson ABI checks\n')
        f.write('This directory is managed automatically unless desired by the user\n')
        f.close()

    # Move to abi folder
    os.chdir(abi_folder)
    abi_dump=tag+'-'+comp+'-'+arch+'-abi_dump'
    # Download and untar abi dump if not present
    if not exists(abi_dump):
        # Check DPDK_ABI_TAR_URI for the location of the tarballs local or web
        tar_uri_env = 'DPDK_ABI_TAR_URI'
        if tar_uri_env in os.environ:
            abi_tar_uri = os.environ[tar_uri_env]
            if abi_tar_uri.startswith('http'):
                # Download the required tarball
                tar_loc = '{}.tar.gz'.format(join(abi_tar_uri,abi_dump))
                r = requests.get(tar_loc)
                if r.status_code == 200:
                    with open('{}.tar.gz'.format(abi_dump), 'wb') as f:
                        f.write(r.content)
            else:
                abi_tar_uri = abspath(abi_tar_uri)
                try:
                    shutil.copy('{}.tar.gz'.format(join(abi_tar_uri,abi_dump)), '.')
                except FileNotFoundError as error:
                    pass
        if not isfile(abi_dump+'.tar.gz'):
            call_exec([join(devtools_path,'gen-abi-tarball.py'), '-t', tag, '-a', arch])
            if not isfile(abi_dump+'.tar.gz'):
                print('ERROR ABI check generation failed', file=sys.stderr)
                exit(1)
        f = tarfile.open('{}.tar.gz'.format(abi_dump))
        f.extractall()
        os.remove('{}.tar.gz'.format(abi_dump))

    # Tell user where specified directory is
    print(abspath(abi_dump))

if __name__ == "__main__":
    main()

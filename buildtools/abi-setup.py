#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

import sys
import os
import argparse

# Get command line arguments
parser = argparse.ArgumentParser(usage='\rThis script is intended to setup ABI dumps for meson to perform ABI checks\n'+
                                       'Supported environmental variables\n'+
                                       '\t- DPDK_ABI_DUMPS_PATH: Can be used to specify a custom directory for the systems dump directories.\n'+
                                       '\t- CC: The required compiler will be determined using this environmental variable.\n'+
                                       '\t- DPDK_ABI_TAR_URI: Can be used to specify a location that the script can pull prebuilt or cached dump archives from. This can be a remote http location or a local directory.\n')
parser.add_argument('-t', '--tag', dest='tag', type=str, help='DPDK tag e.g. latest or v20.11')
parser.add_argument('-d', '--dpdk', dest='dpdk', type=str, help='Path to DPDK source directory')
args = parser.parse_args()

# Get the DPDK tag if not supplied set as latest
if args.tag:
    user_tag = args.tag
else:
    user_tag = 'latest'

tag = ''
# If the user did not supply tag or wants latest then get latest tag
if user_tag == 'latest':
    # Get latest quarterly build tag from git repo
    tag = os.popen('git ls-remote --tags http://dpdk.org/git/dpdk | grep -v "rc\|{}" | tail -n 1 | sed "s/.*\///"').read().strip()
else:
    tag = user_tag
    # If the user supplied tag does not exist then fail
    tag_check = int(os.popen('git ls-remote http://dpdk.org/git/dpdk refs/tags/'+tag+' | wc -l').read().strip())
    if tag_check != 1:
        print('ERROR supplied tag does not exist in DPDK repo')
        exit()

# Get the specified compiler from system
comp_env = 'CC'
if comp_env in os.environ:
    comp = os.environ[comp_env]
else:
    comp = 'gcc'

# Get the systems architecture
arch = os.popen('uname -m').read().strip()

# Get devtools path
devtools_path = ''
if args.dpdk:
    devtools_path = os.path.abspath(os.path.join(args.dpdk,'devtools'))
else:
    print('ERROR DPDK source directory must be specified')
    exit()

# Get the abi dumps folder from args or env fail if none supplied
abi_folder = ''
abi_env = 'DPDK_ABI_DUMPS_PATH'
if abi_env in os.environ:
    abi_folder = os.path.abspath(os.environ[abi_env])
else:
    abi_folder = os.path.abspath(os.path.join(args.dpdk,'abi_dumps'))

# If the directory doesn't exist create it and add a README to explain what it does
if not os.path.exists(abi_folder):
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
if not os.path.exists(abi_dump):
    # Check DPDK_ABI_TAR_URI for the location of the tarballs local or web
    tar_uri_env = 'DPDK_ABI_TAR_URI'
    if tar_uri_env in os.environ:
        abi_tar_uri = os.environ[tar_uri_env]
        if abi_tar_uri.startswith('http'):
            # Wget the required tarball
            os.popen('wget '+os.path.join(abi_tar_uri,abi_dump)+'.tar.gz >/dev/null 2>&1').read()
        else:
            abi_tar_uri = os.path.abspath(abi_tar_uri)
            os.popen('cp '+os.path.join(abi_tar_uri,abi_dump)+'.tar.gz . >/dev/null 2>&1').read()
    # Check tarball was downloaded
    if os.path.isfile(abi_dump+'.tar.gz'):
        os.popen('tar -xzf '+abi_dump+'.tar.gz >/dev/null 2>&1').read()
        os.popen('rm -rf '+abi_dump+'.tar.gz').read()
    # If the tarball was not found then generate it
    else:
        os.popen(os.path.join(devtools_path,'gen-abi-tarball.py')+' -t '+tag+' -a '+arch+' >/dev/null 2>&1').read()
        if not os.path.isfile(abi_dump+'.tar.gz'):
            print('ERROR ABI check generation failed '+os.path.join(devtools_path,'gen-abi-tarball.py')+' -t '+tag+' -a '+arch)
            exit()
        os.popen('tar -xzf '+abi_dump+'.tar.gz >/dev/null 2>&1').read()
        os.popen('rm -rf '+abi_dump+'.tar.gz').read()

# Tell user where specified directory is
print(os.path.abspath(abi_dump))

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

import sys
import os
import argparse

# Get command line arguments
parser = argparse.ArgumentParser(usage='\rThis script is intended to generate ABI dump tarballs\n'+
                                       'Supported environmental variables\n'+
                                       '\t- CC: The required compiler will be determined using this environmental variable.\n')
parser.add_argument('-t', '--tag', type=str, dest='tag', help='DPDK tag e.g. latest or v20.11')
parser.add_argument('-cf', '--cross-file', type=str, dest='crosscompile', help='Set the location of a cross compile config')
parser.add_argument('-a', '--arch', type=str, dest='arch', help='Arch arm or x86_64')
args = parser.parse_args()

# Get the DPDK tag if not supplied set as latest
if args.tag:
    user_tag = args.tag
else:
    user_tag = 'latest'
    print('No tag supplied defaulting to latest')

# Get the cross-compile option
if args.crosscompile:
    cross_comp = args.crosscompile
    if not args.arch:
        print('ERROR Arch must be set using -a when using cross compile')
        exit()
    cross_comp = os.path.abspath(cross_comp)
    cross_comp_meson = '--cross-file '+cross_comp
else:
    cross_comp = ''
    cross_comp_meson = ''

# Get the required system architecture if not supplied set as x86_64
if args.arch:
    arch = args.arch
else:
    arch = os.popen('uname -m').read().strip()
    print('No system architecture supplied defaulting to '+arch)

tag = ''
# If the user did not supply tag or wants latest then get latest tag
if user_tag == 'latest':
    # Get latest quarterly build tag from git repo
    tag = os.popen('git ls-remote --tags http://dpdk.org/git/dpdk | grep -v "rc\|{}" | tail -n 1 | sed "s/.*\///"').read().strip()
else:
    tag = user_tag
    # If the user supplied tag is not in the DPDK repo then fail
    tag_check = int(os.popen('git ls-remote http://dpdk.org/git/dpdk refs/tags/'+tag+' | wc -l').read().strip())
    if tag_check != 1:
        print('ERROR supplied tag does not exist in DPDK repo')
        exit()

# Get the specified compiler from system
comp_env = 'CC'
if comp_env in os.environ:
    comp = os.environ[comp_env]
    comp_default = ''
else:
    print('No compiler specified, defaulting to gcc')
    comp = 'gcc'
    comp_default = 'CC=gcc'

# Print the configuration to the user
print('\nSelected Build: '+tag+', Compiler: '+comp+', Architecture: '+arch+', Cross Compile: '+cross_comp)

# Store the base directory script is working from
baseDir = os.getcwd()
# Store devtools dir
devtoolsDir = os.path.abspath(os.path.dirname(os.path.realpath(sys.argv[0])))

# Create directory for DPDK git repo and build
try:
    os.mkdir('dump_dpdk')
except OSError as error:
    print('ERROR The dump_dpdk directory could not be created, ensure it does not exist before start')
    exit()
os.chdir('dump_dpdk')
# Clone DPDK and switch to specified tag
print('Cloning '+tag+' from DPDK git')
os.popen('git clone --quiet http://dpdk.org/git/dpdk >/dev/null').read()
os.chdir('dpdk')
os.popen('git checkout --quiet '+tag+' >/dev/null').read()

# Create build folder with meson and set debug build and cross compile (if needed)
print('Configuring Meson')
os.popen(comp_default+' meson dumpbuild '+cross_comp_meson+' >/dev/null').read()
os.chdir('dumpbuild')
os.popen('meson configure -Dbuildtype=debug >/dev/null').read()
print('Building DPDK . . .')
#Build DPDK with ninja
os.popen('ninja >/dev/null').read()
gccDir = os.getcwd()

# Create directory for abi dump files
dumpDir = os.path.join(baseDir,tag+'-'+comp+'-'+arch+'-abi_dump')
try:
    os.mkdir(dumpDir)
except OSError as error:
    print('ERROR The '+dumpDir+' directory could not be created')
    os.popen('rm -rf '+os.path.join(baseDir,'dump_dpdk')).read()
    exit()

# Create dump files and output to dump directory
print('Generating ABI dump files')
genabiout = os.popen(os.path.join(devtoolsDir,'gen-abi.sh')+' '+gccDir).read()
os.popen('cp dump/* '+dumpDir).read()

# Compress the dump directory
print('Creating Tarball of dump files')
os.chdir(baseDir)
origSize = os.popen('du -sh '+dumpDir+' | sed "s/\s.*$//"').read()
os.popen('tar -czf '+dumpDir.split('/')[-1]+'.tar.gz '+dumpDir.split('/')[-1]+' >/dev/null').read()
newSize = os.popen('du -sh '+dumpDir+'.tar.gz | sed "s/\s.*$//"').read()

# Remove all temporary directories
print('Cleaning up temporary directories')
os.popen('rm -rf '+dumpDir).read()
os.popen('rm -rf '+os.path.join(baseDir,'dump_dpdk')).read()

#Print output of the script to the user
print('\nDump of DPDK ABI '+tag+' is available in '+dumpDir.split('/')[-1]+'.tar.gz (Original Size: '+origSize.strip()+', Compressed Size:'+newSize.strip()+')\n')

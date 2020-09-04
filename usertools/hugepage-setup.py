#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Microsoft Corporation
#
# Script to query and setup huge pages for DPDK applications.

import sys
import os
import re
import getopt
import glob
from os.path import exists, basename
from math import log2

# systemd mount point for huge pages
HUGEDIR = '/dev/hugepages'

# Standard binary prefix
BINARY_PREFIX = "KMG"

# command-line flags
show_flag = None
reserve_kb = None
clear_flag = None
hugepagesize_kb = None
mount_flag = None
unmount_flag = None
numa_node = None


def usage():
    '''Print usage information for the program'''
    mnt = HUGEDIR
    argv0 = basename(sys.argv[0])
    print("""
Usage:
------
    %(argv0)s [options]

Options:
    --help, --usage:
        Display usage information and quit

    -s, --show:
        Print the current huge page configuration.

    --setup:
        Simplified version of clear, umount, reserve, mount operations

    -c, --clear:
        Remove all huge pages

    -r, --reserve:
        Reserve huge pages. The size specified is in bytes, with
        optional K, M or G suffix. The size must be a multiple
        of the page size.

    -p, --pagesize
        Choose page size to use. If not specified, the default
        system page size will be used.

    -n, --node
	Select numa node to reserve pages on.
	If not specified, pages will be reserved on all nodes.

    -m, --mount
        Mount the system huge page directory %(mnt)s

    -u, --umount
        Unmount the system huge page directory %(mnt)s


Examples:
---------

To display current huge page settings:
    %(argv0)s -s

To a complete setup of with 2 Gigabyte of 1G huge pages:
    %(argv0)s -p 1G --setup 2G

Equivalent to:
    %(argv0)s -p 1G -c -u -r 2G -m

To clear existing huge page settings and umount %(mnt)s
    %(argv0)s -c -u

    """ % locals())


def fmt_memsize(sz_k):
    '''Format memory size in kB into conventional format'''
    if sz_k < 1024:
        return sz_k
    l = int(log2(sz_k) / 10)
    return '{}{}b'.format(int(sz_k / (2**(l * 10))), BINARY_PREFIX[l])


def get_memsize(arg):
    '''Convert memory size with suffix to kB'''
    m = re.match(r'(\d+)([' + BINARY_PREFIX + r']?)$', arg.upper())
    if m is None:
        sys.exit('{} is not a valid page size'.format(arg))
    num = float(m.group(1))
    suffix = m.group(2)
    if suffix == "":
        return int(num / 1024)
    idx = BINARY_PREFIX.find(suffix)
    return int(num * (2**(idx * 10)))


def is_numa():
    '''Test if NUMA is necessary on this system'''
    return exists('/sys/devices/numa/node')


def get_hugepages(path):
    '''Read number of reserved pages'''
    with open(path + '/nr_hugepages') as f:
        return int(f.read())
    return 0


def show_numa_pages():
    print('Node Pages Size')
    for n in glob.glob('/sys/devices/system/node/node*'):
        path = n + '/hugepages'
        node = n[29:]  # slice after /sys/devices/system/node/node
        for d in os.listdir(path):
            sz = int(d[10:-2])  # slice out of hugepages-NNNkB
            nr_pages = get_hugepages(path + '/' + d)
            if nr_pages > 0:
                pg_sz = fmt_memsize(sz)
                print('{:<4} {:<5} {}'.format(node, nr_pages, pg_sz))


def show_non_numa_pages():
    print('Pages Size')
    path = '/sys/kernel/mm/hugepages'
    for d in os.listdir(path):
        sz = int(d[10:-2])
        nr_pages = get_hugepages(path + '/' + d)
        if nr_pages > 0:
            pg_sz = fmt_memsize(sz)
            print('{:<5} {}'.format(nr_pages, pg_sz))


def show_pages():
    '''Show existing huge page settings'''
    if is_numa():
        show_numa_pages()
    else:
        show_non_numa_pages()


def clear_numa_pages():
    for path in glob.glob(
            '/sys/devices/system/node/node*/hugepages/hugepages-*'):
        with open(path + '/nr_hugepages', 'w') as f:
            f.write('\n0')


def clear_non_numa_pages():
    for path in glob.glob('/sys/kernel/mm/hugepages/hugepages-*'):
        with open(path + '/nr_hugepages', 'w') as f:
            f.write('0\n')


def clear_pages():
    '''Clear all existing huge page mappings'''
    if is_numa():
        clear_numa_pages()
    else:
        clear_non_numa_pages()


def default_size():
    '''Get default huge page size from /proc/meminfo'''
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith('Hugepagesize:'):
                return int(line.split()[1])
    return None


def set_numa_pages(nr_pages, hugepgsz):
    if numa_node:
        nodes = ['/sys/devices/system/node/node{}/hugepages'.format(numa_node)]
    else:
        nodes = glob.glob('/sys/devices/system/node/node*/hugepages')

    for n in nodes:
        path = '{}/hugepages-{}kB/nr_hugepages'.format(n, hugepgsz)
        if not exists(path):
            sys.exit(
                '{}Kb is not a valid system huge page size'.format(hugepgsz))
        with open(path, 'w') as f:
            f.write('{}\n'.format(nr_pages))


def set_non_numa_pages(nr_pages, hugepgsz):
    path = '/sys/kernel/mm/hugepages/hugepages-{}kB/nr_hugepages'.format(
        hugepgsz)
    if not exists(path):
        sys.exit('{}Kb is not a valid system huge page size'.format(hugepgsz))

    with open(path, 'w') as f:
        f.write('{}\n'.format(nr_pages))


def set_pages(pages, hugepgsz):
    '''Sets the number of huge pages to be reserved'''
    if is_numa():
        set_numa_pages(pages, hugepgsz)
    else:
        set_non_numa_pages(pages, hugepgsz)


def mount_huge(pagesize):
    cmd = "mount -t hugetlbfs"
    if pagesize:
        cmd += ' -o pagesize={}'.format(pagesize)
    cmd += ' nodev {}'.format(HUGEDIR)
    os.system(cmd)


def show_mount():
    mounted = None
    with open('/proc/mounts') as f:
        for line in f:
            fields = line.split()
            if fields[2] != 'hugetlbfs':
                continue
            if not mounted:
                print("Hugepages mounted on:", end=" ")
                mounted = True
            print(fields[1], end=" ")
    if mounted:
        print()
    else:
        print("Hugepages not mounted")


def parse_args():
    '''Parses the command-line arguments given by the user and takes the
    appropriate action for each'''
    global clear_flag
    global hugepagesize_kb
    global mount_flag
    global numa_node
    global reserve_kb
    global show_flag
    global unmount_flag

    if len(sys.argv) <= 1:
        usage()
        sys.exit(0)

    try:
        opts, args = getopt.getopt(sys.argv[1:], "r:p:csmun:", [
            "help", "usage", "show", "clear", "setup=", "reserve=",
            "pagesize=", "node=", "mount", "unmount"
        ])
    except getopt.GetoptError as error:
        print(str(error))
        print("Run '%s --usage' for further information" % sys.argv[0])
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('--help', '--usage'):
            usage()
            sys.exit(0)
        elif opt == '--setup':
            clear_flag = True
            unmount_flag = True
            reserve_kb = get_memsize(arg)
            mount_flag = True
        elif opt in ('--show', '-s'):
            show_flag = True
        elif opt in ('--clear', '-c'):
            clear_flag = True
        elif opt in ('--reserve', '-r'):
            reserve_kb = get_memsize(arg)
        elif opt in ('--pagesize', '-p'):
            hugepagesize_kb = get_memsize(arg)
        elif opt in ('--unmount', '-u'):
            unmount_flag = True
        elif opt in ('--mount', '-m'):
            mount_flag = True
        elif opt in ('--node', '-n'):
            if not arg.isdigit():
                sys.exit('Numeric value for numa node expected')
            numa_node = arg


def do_arg_actions():
    '''do the actual action requested by the user'''
    global hugepagesize_kb

    if clear_flag:
        clear_pages()
    if unmount_flag:
        os.system("umount " + HUGEDIR)
    if reserve_kb:
        if hugepagesize_kb is None:
            hugepagesize_kb = default_size()
        if reserve_kb % hugepagesize_kb != 0:
            sys.exit('{} is not a multiple of page size {}'.format(
                reserve_kb, hugepagesize_kb))
        nr_pages = int(reserve_kb / hugepagesize_kb)
        set_pages(nr_pages, hugepagesize_kb)
    if mount_flag:
        mount_huge(hugepagesize_kb * 1024)
    if show_flag:
        show_pages()
        print()
        show_mount()


def main():
    parse_args()
    do_arg_actions()


if __name__ == "__main__":
    main()

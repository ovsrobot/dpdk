# Copyright (c) 2020 Microsoft Corporation
#
# Script to query and setup huge pages for DPDK applications.

import sys
import os
import re
import getopt
import glob
from os.path import exists, basename

# convention for where to mount huge pages
hugedir = '/dev/hugepages'

# command-line flags
show_flag = None
reserve_kb = None
clear_flag = None
hugepagesize_kb = None
mount_flag = None
unmount_flag = None


def usage():
    '''Print usage information for the program'''
    global hugedir
    mnt = hugedir
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


def fmt_memsize(sz):
    '''Format memory size in conventional format'''
    sz_kb = int(sz)
    if sz_kb >= 1024 * 1024:
        return '{}Gb'.format(sz_kb / (1024 * 1024))
    elif sz_kb >= 1024:
        return '{}Mb'.format(sz_kb / 1024)
    else:
        return '{}Kb'.format(sz_kb)


def get_memsize(arg):
    '''Convert memory size with suffix to kB'''
    m = re.match('(\d+)([GMKgmk]?)$', arg)
    if m is None:
        sys.exit('{} is not a valid page size'.format(arg))

    num = float(m.group(1))
    suf = m.group(2)
    if suf == "G" or suf == "g":
        return int(num * 1024 * 1024)
    elif suf == "M" or suf == "m":
        return int(num * 1024)
    elif suf == "K" or suf == "k":
        return int(num)
    else:
        return int(num / 1024.)


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
            sz = d[10:-2]  # slice out of hugepages-NNNkB
            nr_pages = get_hugepages(path + '/' + d)
            if nr_pages > 0:
                pg_sz = fmt_memsize(sz)
                print('{:<4} {:<5} {}'.format(node, nr_pages, pg_sz))


def show_non_numa_pages():
    print('Pages Size')
    path = '/sys/kernel/mm/hugepages'
    for d in os.listdir(path):
        sz = d[10:-2]
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
    for n in glob.glob('/sys/devices/system/node/node*/hugepages'):
        path = '{}/hugepages-{}kB'.format(n, hugepgsz)
        if not exists(path):
            sys.exit(
                '{}Kb is not a valid system huge page size'.format(hugepgsz))

        with open(path + '/nr_hugepages', 'w') as f:
            f.write('{}\n'.format(nr_pages))


def set_non_numa_pages(nr_pages, hugepgsz):
    path = '/sys/kernel/mm/hugepages/hugepages-{}kB'.format(hugepgsz)
    if not exists(path):
        sys.exit('{}Kb is not a valid system huge page size'.format(hugepgsz))

    with open(path + '/nr_hugepages', 'w') as f:
        f.write('{}\n'.format(nr_pages))


def set_pages(pages, hugepgsz):
    '''Sets the numberof huge pages to be reserved'''
    if is_numa():
        set_numa_pages(pages, hugepgsz)
    else:
        set_non_numa_pages(pages, hugepgsz)


def mount_huge(pagesize):
    global hugedir
    cmd = "mount -t hugetlbfs" + hugedir
    if pagesize:
        cmd += ' -o pagesize={}'.format(pagesize)
    cmd += ' nodev {}'.format(hugedir)
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
    global show_flag
    global reserve_kb
    global hugepagesize_kb
    global args

    if len(sys.argv) <= 1:
        usage()
        sys.exit(0)

    try:
        opts, args = getopt.getopt(sys.argv[1:], "r:p:csmu", [
            "help", "usage", "show", "clear", "setup=", "eserve=", "pagesize=",
            "mount", "unmount"
        ])
    except getopt.GetoptError as error:
        print(str(error))
        print("Run '%s --usage' for further information" % sys.argv[0])
        sys.exit(1)

    for opt, arg in opts:
        if opt == "--help" or opt == "--usage":
            usage()
            sys.exit(0)
        if opt == "--setup":
            clear_flag = True
            unmount_flag = True
            reserve_kb = get_memsize(arg)
            mount_flag = True
        if opt == "--show" or opt == "-s":
            show_flag = True
        if opt == "--clear" or opt == "-c":
            clear_flag = True
        if opt == "--reserve" or opt == "-r":
            reserve_kb = get_memsize(arg)
        if opt == "--pagesize" or opt == "-p":
            hugepagesize_kb = get_memsize(arg)
        if opt == "--unmount" or opt == "-u":
            unmount_flag = True
        if opt == "--mount" or opt == "-m":
            mount_flag = True


def do_arg_actions():
    '''do the actual action requested by the user'''
    global clear_flag
    global show_flag
    global hugepagesize_kb
    global reserve_kb

    if clear_flag:
        clear_pages()
    if unmount_flag:
        os.system("umount " + hugedir)
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

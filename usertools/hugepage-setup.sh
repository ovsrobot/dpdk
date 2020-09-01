#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

usage()
{
    echo "Usage: $0 size [pagesize]"
    echo "  size is in bytes with optional M or G suffix"
    echo "  pagesize is the pagesize to use"
    exit 1
}

get_pagesize()
{
    SIZE="$1"

    if [[ "$SIZE" =~ ^[0-9]+G$ ]]; then
	echo $((${SIZE%%G} * 1024 * 1024))
    elif [[ "$SIZE" =~ ^[0-9]+M$ ]]; then
	echo $((${SIZE%%M} * 1024))
    elif [[ "$SIZE" =~ ^[0-9]+K$ ]]; then
	echo ${SIZE%%K}
    elif [[ "$SIZE" =~ ^[0-9]+$ ]]; then
	if [ $((SIZE % 1024)) -ne 0 ]; then
	    exit 1
	else
	    echo $((SIZE / 1024))
	fi
    else
	exit 1
    fi
}

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
    echo "Creating /mnt/huge and mounting as hugetlbfs"
    mkdir -p /mnt/huge

    grep -s '/mnt/huge' /proc/mounts > /dev/null
    if [ $? -ne 0 ] ; then
	mount -t hugetlbfs -o pagesize=${PAGESIZE} nodev /mnt/huge
    fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
    echo "Unmounting /mnt/huge and removing directory"
    grep -s '/mnt/huge' /proc/mounts > /dev/null
    if [ $? -eq 0 ] ; then
	umount /mnt/huge
    fi

    if [ -d /mnt/huge ] ; then
	rm -R /mnt/huge
    fi
}
#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
    echo > .echo_tmp
    for d in /sys/devices/system/node/node? ; do
	for sz in $d/hugepages/hugepages-* ; do
	    echo "echo 0 > ${sz}/nr_hugepages" >> .echo_tmp
	done
    done
    echo "Removing currently reserved hugepages"
    sh .echo_tmp
    rm -f .echo_tmp

    remove_mnt_huge
}

#
# Creates hugepages.
#
set_non_numa_pages()
{
    path=/sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}kB
    if [ ! -d $path ]; then
	>&2 echo "${HUGEPGSZ}K is not a valid huge page size"
	exit 1
    fi
    for sz in /sys/kernel/mm/hugepages/hugepages-* ; do
	echo "echo 0 > ${sz}/nr_hugepages" >> .echo_tmp
    done

    echo "Reserving $PAGES hugepages of size $HUGEPGSZ kB"
    echo $PAGES > $path/nr_hugepages

    create_mnt_huge
}

#
# Creates hugepages on specific NUMA nodes.
#
set_numa_pages()
{
	clear_huge_pages

	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		node=$(basename $d)
		path="$d/hugepages/hugepages-${HUGEPGSZ}kB"
		if [ ! -d $path ]; then
		    >&2 echo "${HUGEPGSZ}K is not a valid huge page size"
		    exit 1
		fi

		echo "echo $Pages > $path" >> .echo_tmp
	done
	echo "Reserving $PAGES hugepages of size $HUGEPGSZ kB (numa)"
	sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

#
# Need size argument
#
[ $# -ge 1 ] || usage

#
# Convert from size to pages
#
KSIZE=$(get_pagesize $1)
if [ $? -ne 0 ]; then
    >&2 echo "Invalid huge area size: $1"
    exit 1
fi

#
# Optional second argument is pagesize
#
if [ $# -gt 1 ]; then
    HUGEPGSZ=$(get_pagesize $2)
    if [ $? -ne 0 ]; then
	>&2 echo "Invalid huge page size: $2"
	exit 1
    fi
else
    HUGEPGSZ=$(awk '/^Hugepagesize/ { print $2 }' /proc/meminfo )
fi

if [ $((KSIZE % HUGEPGSZ)) -ne 0 ] ; then
    echo "Invalid number of huge pages $KSIZE K, should be multiple of $HUGEPGSZ K"
    exit 1
fi

PAGES=$((KSIZE / HUGEPGSZ))
PAGESIZE=$((HUGEPGSZ * 1024))

#
# Do NUMA if necessary
#
if [ -e /sys/devices/numa/node ]; then
    set_numa_pages
else
    set_non_numa_pages
fi

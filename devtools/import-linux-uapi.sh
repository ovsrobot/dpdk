#!/bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Red Hat, Inc.

#
# Import Linux Kernel uAPI header file
#

base_url="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/"
base_path="linux-headers/uapi/"

print_usage()
{
	echo "Usage: $(basename $0) [-h] file version"
	echo "Example of valid file: linux/vfio.h"
	echo "Example of valid version: v6.10"
}

while getopts hv ARG ; do
	case $ARG in
		h )
			print_usage
			exit 0
			;;
		? )
			print_usage
			exit 1
			;;
	esac
done
shift $(($OPTIND - 1))

if [ $# -ne 2 ]; then
	print_usage
	exit 1
fi

file=$1
version=$2

url="${base_url}${file}?h=${version}"
path="${base_path}${file}"

cd $(dirname $0)/..
curl -s -f --create-dirs -o $path $url

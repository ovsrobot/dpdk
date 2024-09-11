#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Red Hat, Inc.

#
# Check Linux Kernel uAPI header files
#

base_url="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/"
base_path="linux-headers/uapi/"
errors=0
version=""

print_usage()
{
	echo "Usage: $(basename $0) [-h]"
}

check_uapi_header() {
	path=$1
	file=${1#$base_path}

	cp -f $path $tmpinput1

	# Restore includes fixups done by import-linux-uapi.sh
	sed -i "s|//#include <linux/compiler.h>|#include <linux/compiler.h>|g" $tmpinput1
	sed -i "s|#include <uapi/|#include <|g" $tmpinput1

	url="${base_url}${file}?h=${version}"
	echo -n "Checking $file... "
	curl -s -f -o $tmpinput2 $url
	if [ $? -ne 0 ]; then
		echo "Failed to download $url"
		exit 1
	fi

	diff -q $tmpinput1 $tmpinput2 >/dev/null
	if [ $? -ne 0 ]; then
		echo "KO"
		diff -u $tmpinput1 $tmpinput2
		errors=$((errors+1))
	else
		echo "OK"
	fi
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
if [ $# -ne 0 ]; then
	print_usage
	exit 1
fi

cd $(dirname $0)/..

tmpinput1=$(mktemp -t dpdk.checkuapi.XXXXXX)
tmpinput2=$(mktemp -t dpdk.checkuapi.XXXXXX)
trap "rm -f '$tmpinput1 $tmpinput2'" INT

version=$(< ${base_path}/version)

echo "Checking imported headers for version ${version}"

for filename in $(find $base_path -name "*.h" -type f); do
	check_uapi_header "${filename}" </dev/null
done

echo "$errors error(s) found"

rm -f $tmpinput1 $tmpinput2
trap - INT

exit $errors

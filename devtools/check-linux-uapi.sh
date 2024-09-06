#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Red Hat, Inc.

#
# Import Linux Kernel uAPI header file
#

base_url="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/"
base_path="linux-headers/uapi/"
errors=0

print_usage()
{
	echo "Usage: $(basename $0) [-h]"
}

check_uapi_header() {
	path=$1
	file=${1//"$base_path"/}
	version=$(git log --format=%b -1 $path | sed -ne 's/^uAPI Version: \(.*\)$/\1/p')

	url="${base_url}${file}?h=${version}"
	echo -n "Checking $file for version $version... "
	curl -s -f -o $tmpinput $url
	if [ $? -ne 0 ]; then
		echo "Failed to download $url"
		exit 1
	fi

	diff -q $path $tmpinput >/dev/null
	if [ $? -ne 0 ]; then
		echo "KO"
		diff -u $path $tmpinput
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

tmpinput=$(mktemp -t dpdk.checkuapi.XXXXXX)
trap "rm -f '$tmpinput'" INT

while IFS= read -d '' -r filename; do
	check_uapi_header "${filename}" </dev/null
done < <(find $base_path -name "*.h" -type f -print0)

echo "$errors error(s) found"

rm -f $tmpinput
trap - INT

exit $errors

#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Red Hat, Inc.

#
# Import Linux Kernel uAPI header file
#

base_url="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/"
base_path="linux-headers/uapi/"
version=""
file=""

print_usage()
{
	echo "Usage: $(basename $0) [-h] [-a FILE] [-u VERSION]"
	echo "-a FILE      import Linux header file. E.g. linux/vfio.h"
	echo "-u VERSION   update imported list of Linux headers to a given version. E.g. v6.10"
}

version_valid() {
    printf '%s\n%s' "$1" "$2" | sort -C -V
}

update_headers()
{
	local header=${filename//"$base_path"}
	local url
	local path

	echo "Updating to $version"
	while IFS= read -d '' -r filename; do
		header=${filename//"$base_path"/}
		url="${base_url}${header}?h=${version}"
		path="${base_path}${header}"
		curl -s -f -o $path $url
	done < <(find $base_path -name "*.h" -type f -print0)
}

import_header()
{
	local include
	local import
	local header=$1

	local url="${base_url}${header}?h=${version}"
	local path="${base_path}${header}"

	curl -s -f --create-dirs -o $path $url

	for include in $(sed -ne 's/^#include <\(.*\)>$/\1/p' $path); do
		if [ ! -f "${base_path}${include}" ]; then
			read -p "Import $include (y/n): " import < /dev/tty && [ "$import" = 'y' ] || continue
			echo "Importing $include for $path"
			import_header "$include"
		fi
	done
}

fixup_includes()
{
	local path=$1

	# Do not include linux/compiler.h as done by make headers
	sed -i "s|^#include <linux/compiler.h>|//#include <linux/compiler.h>|g" $path

	# Prepend include path with "uapi/" if the header is imported
	for include in $(sed -ne 's/^#include <\(.*\)>$/\1/p' $path); do
		if [ -f "${base_path}${include}" ]; then
			sed -i "s|${include}|uapi/${include}|g" $path
		fi
	done
}

while getopts a:u:hv opt ; do
	case ${opt} in
		a )
			file=$OPTARG
			;;
		u )
			version=$OPTARG
			;;
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

cd $(dirname $0)/..

current_version=$(< ${base_path}/version)

if [ -n "${version}" ]; then
	version_valid "$version" "$current_version"
	if [ $? -eq 0 ]; then
		echo "Headers already up to date ($current_version >= $version)"
		version=$current_version
	else
		update_headers
	fi
else
	echo "Version not specified, using current version ($current_version)"
	version=$current_version
fi

if [ -n "${file}" ]; then
	import_header $file
fi

for filename in $(find $base_path -name "*.h" -type f); do
	fixup_includes "${filename}" </dev/null
done

echo $version > ${base_path}/version

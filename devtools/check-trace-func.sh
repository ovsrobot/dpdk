#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

selfdir=$(dirname $(readlink -f $0))
. $selfdir/common-func.sh

libdir="ethdev"
check_for_trace_call()
{
	mapdb="$2"
	ret=0

	while read -r mname symname secname ar; do
		libp=0
		libname=$(echo $mname | awk 'BEGIN {FS="/"};{print $3}')

		for i in $libdir; do
			if [ $i = $libname ]; then
				libp=1
				break
			fi
		done

		if [ $libp -eq 1 ] && [ "$ar" = "add" ]; then
			if [ "$secname" = "EXPERIMENTAL" ]; then
				# Check if new API is added with trace function call
				if ! devtools/check-trace-func.py $1 $symname; then
					ret=1
					echo -n "ERROR: Function $symname "
					echo "is added without trace call"
				fi
			fi
		fi
	done < "$mapdb"

	return $ret
}

clean_and_exit_on_sig()
{
	rm -rf "$mapfile"
}

trap clean_and_exit_on_sig EXIT

mapfile=$(mktemp -t dpdk.mapdb.XXXXXX)

build_map_changes "$1" "$mapfile"
check_for_trace_call "$1" "$mapfile"

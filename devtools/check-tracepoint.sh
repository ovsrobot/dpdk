#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

selfdir=$(dirname $(readlink -f $0))
. $selfdir/common-func.sh

# Library for trace check
libdir="cryptodev"

# Functions for which the trace check can be skipped
skiplist="$selfdir/trace-skiplist.txt"

check_for_tracepoint()
{
	mapdb="$2"
	ret=0

	while read -r mname symname secname ar; do
		libp=0
		skip_sym=0
		libname=$(echo $mname | awk 'BEGIN {FS="/"};{print $3}')

		for lib in $libdir; do
			if [ $lib = $libname ]; then
				libp=1
				break
			fi
		done

		for sym in $(cat $skiplist); do
			if [ $sym = $symname ]; then
				skip_sym=1
				break
			fi
		done

		if [ $libp -eq 1 ] && [ $skip_sym -eq 0 ] && [ "$ar" = "add" ]; then
			if [ "$secname" = "EXPERIMENTAL" ]; then
				# Check if new API is added with tracepoint
				if ! devtools/check-tracepoint.py $1 $symname; then
					ret=1
					echo -n "ERROR: New function $symname is added "
					echo -n "without a tracepoint. Please add a tracepoint "
					echo -n "or add the function $symname in "
					echo "devtools/trace-skiplist.txt to skip this error."
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
check_for_tracepoint "$1" "$mapfile"

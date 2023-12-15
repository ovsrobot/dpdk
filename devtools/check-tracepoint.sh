#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

selfdir=$(dirname $(readlink -f $0))
. $selfdir/symbol-map-util.sh

# Library for trace check
libdir="cryptodev ethdev eventdev mempool"

# Functions for which the trace check can be skipped
skiplist="$selfdir/trace-skiplist.txt"

find_trace_fn()
{
	local fname="$1"

	cat "$fname" | awk -v symname="$2 *\\\(" '
		# Initialize the variables.
		# The variable symname provides a pattern to match
		# "function_name(", zero or more spaces can be present
		# between function_name and (.
		BEGIN {state=0; ln_pth=0}

		# Matches the function name, set state=1.
		$0 ~ symname {state=1}

		# If closing parentheses with semicolon ");" is found, then it
		# is not the function definition.
		/) *;/ {
			if (state == 1) {
				state=0
			}
		}

		/)/ {
			if (state == 1) {
				state=2
				ln_pth=NR
				next
			}
		}

		# If closing parentheses and then opening braces is found in
		# adjacent line, then this is the start of function
		# definition. Check for tracepoint in the function definition.
		# The tracepoint has _trace_ in its name.
		/{/ {
			if (state == 2) {
				if (ln_pth != NR - 1) {
					state=0
					next
				}
				while (index($0, "}") != 2) {
					if (index($0, "_trace_") != 0) {
						exit 0
					}
					if (getline <= 0) {
						break
					}
				}
				exit 1
			}
		}
	'
}

check_for_tracepoint()
{
	local patch="$1"
	local mapdb="$2"
	local skip_sym
	local libname
	local secname
	local mname
	local ret=0
	local pdir
	local libp
	local libn
	local sym
	local ar

	while read -r mname symname secname ar; do
		pdir=$(echo $mname | awk 'BEGIN {FS="/"};{print $2}')
		libname=$(echo $mname | awk 'BEGIN {FS="/"};{print $3}')
		skip_sym=0
		libp=0

		if [ "$pdir" != "lib" ]; then
			continue
		fi

		for libn in $libdir; do
			if [ $libn = $libname ]; then
				libp=1
				break
			fi
		done

		if [ $libp -eq 0 ]; then
			continue
		fi

		for sym in $(cat $skiplist); do
			if [ $sym = $symname ]; then
				skip_sym=1
				break
			fi
		done

		if [ $skip_sym -eq 1 ]; then
			continue
		fi

		if [ "$ar" = "add" ] && [ "$secname" = "EXPERIMENTAL" ]; then
			# Check if new API is added with tracepoint
			find_trace_fn $patch $symname
			if [ $? -eq 1 ]; then
				ret=1
				echo -n "ERROR: New function $symname is added "
				echo -n "without a tracepoint. Please add a tracepoint "
				echo -n "or add the function $symname in "
				echo "devtools/trace-skiplist.txt to skip this error."
			fi
		fi
	done < "$mapdb"

	return $ret
}

trap clean_and_exit_on_sig EXIT

mapfile=`mktemp -t dpdk.mapdb.XXXXXX`
patch=$1
exit_code=1

clean_and_exit_on_sig()
{
	rm -f "$mapfile"
	exit $exit_code
}

build_map_changes "$patch" "$mapfile"
check_for_tracepoint "$patch" "$mapfile"
exit_code=$?
rm -f "$mapfile"

exit $exit_code

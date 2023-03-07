#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Neil Horman <nhorman@tuxdriver.com>
# Copyright(C) 2023 Marvell.

selfdir=$(dirname $(readlink -f $0))

# Library for trace check
libdir="cryptodev ethdev eventdev mempool"

# Functions for which the trace check can be skipped
skiplist="$selfdir/trace-skiplist.txt"

build_map_changes()
{
	local fname="$1"
	local mapdb="$2"

	cat "$fname" | awk '
		# Initialize our variables
		BEGIN {map="";sym="";ar="";sec=""; in_sec=0; in_map=0}

		# Anything that starts with + or -, followed by an a
		# and ends in the string .map is the name of our map file
		# This may appear multiple times in a patch if multiple
		# map files are altered, and all section/symbol names
		# appearing between a triggering of this rule and the
		# next trigger of this rule are associated with this file
		/[-+] [ab]\/.*\.map/ {map=$2; in_map=1; next}

		# The previous rule catches all .map files, anything else
		# indicates we left the map chunk.
		/[-+] [ab]\// {in_map=0}

		# Triggering this rule, which starts a line and ends it
		# with a { identifies a versioned section.  The section name is
		# the rest of the line with the + and { symbols removed.
		# Triggering this rule sets in_sec to 1, which actives the
		# symbol rule below
		/^.*{/ {
			gsub("+", "");
			if (in_map == 1) {
				sec=$(NF-1); in_sec=1;
			}
		}

		# This rule identifies the end of a section, and disables the
		# symbol rule
		/.*}/ {in_sec=0}

		# This rule matches on a + followed by any characters except a :
		# (which denotes a global vs local segment), and ends with a ;.
		# The semicolon is removed and the symbol is printed with its
		# association file name and version section, along with an
		# indicator that the symbol is a new addition.  Note this rule
		# only works if we have found a version section in the rule
		# above (hence the in_sec check) And found a map file (the
		# in_map check).  If we are not in a map chunk, do nothing.  If
		# we are in a map chunk but not a section chunk, record it as
		# unknown.
		/^+[^}].*[^:*];/ {gsub(";","");sym=$2;
			if (in_map == 1) {
				if (in_sec == 1) {
					print map " " sym " " sec " add"
				} else {
					print map " " sym " unknown add"
				}
			}
		}

		# This is the same rule as above, but the rule matches on a
		# leading - rather than a +, denoting that the symbol is being
		# removed.
		/^-[^}].*[^:*];/ {gsub(";","");sym=$2;
			if (in_map == 1) {
				if (in_sec == 1) {
					print map " " sym " " sec " del"
				} else {
					print map " " sym " unknown del"
				}
			}
		}' > "$mapdb"

		sort -u "$mapdb" > "$mapdb.2"
		mv -f "$mapdb.2" "$mapdb"

}

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

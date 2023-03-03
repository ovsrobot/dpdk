#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Neil Horman <nhorman@tuxdriver.com>

selfdir=$(dirname $(readlink -f $0))
. $selfdir/build-symbol-map.sh

is_stable_section() {
	[ "$1" != 'EXPERIMENTAL' ] && [ "$1" != 'INTERNAL' ]
}

check_for_rule_violations()
{
	local mapdb="$1"
	local mname
	local symname
	local secname
	local ar
	local ret=0

	while read mname symname secname ar
	do
		if [ "$ar" = "add" ]
		then

			if [ "$secname" = "unknown" ]
			then
				# Just inform the user of this occurrence, but
				# don't flag it as an error
				echo -n "INFO: symbol $symname is added but "
				echo -n "patch has insufficient context "
				echo -n "to determine the section name "
				echo -n "please ensure the version is "
				echo "EXPERIMENTAL"
				continue
			fi

			oldsecname=$(sed -n \
			"s#$mname $symname \(.*\) del#\1#p" "$mapdb")

			# A symbol can not enter a stable section directly
			if [ -z "$oldsecname" ]
			then
				if ! is_stable_section $secname
				then
					echo -n "INFO: symbol $symname has "
					echo -n "been added to the "
					echo -n "$secname section of the "
					echo "version map"
					continue
				else
					echo -n "ERROR: symbol $symname "
					echo -n "is added in the $secname "
					echo -n "section, but is expected to "
					echo -n "be added in the EXPERIMENTAL "
					echo "section of the version map"
					ret=1
					continue
				fi
			fi

			# This symbol is moving inside a section, nothing to do
			if [ "$oldsecname" = "$secname" ]
			then
				continue
			fi

			# This symbol is moving between two sections (the
			# original section is a stable section).
			# This can be legit, just warn.
			if is_stable_section $oldsecname
			then
				echo -n "INFO: symbol $symname is being "
				echo -n "moved from $oldsecname to $secname. "
				echo -n "Ensure that it has gone through the "
				echo "deprecation process"
				continue
			fi
		else

			if ! grep -q "$mname $symname .* add" "$mapdb" && \
			   is_stable_section $secname
			then
				# Just inform users that stable
				# symbols need to go through a deprecation
				# process
				echo -n "INFO: symbol $symname is being "
				echo -n "removed, ensure that it has "
				echo "gone through the deprecation process"
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
check_for_rule_violations "$mapfile"
exit_code=$?
rm -f "$mapfile"

exit $exit_code

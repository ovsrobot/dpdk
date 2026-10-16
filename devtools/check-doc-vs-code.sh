#! /bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 Mellanox Technologies, Ltd

# Check whether doc & code are in sync.
# Optional argument: check only what changed since a commit.
trusted_commit=$1 # example: origin/main

selfdir=$(dirname $(readlink -f $0))
rootdir=$(readlink -f $selfdir/..)

# speed up by ignoring Unicode details
export LC_COLLATE=C

result=0
error() # <message>
{
	echo "$*"
	result=$(($result + 1))
}

changed_files()
{
	[ -n "$files" ] ||
		files=$(git diff-tree --name-only -r $trusted_commit..)
	echo "$files"
}

has_code_change() # <pattern>
{
	test -n "$(git log --format='%h' -G"$1" $trusted_commit..)"
}

has_file_change() # <pattern>
{
	changed_files | grep -q "$1"
}

changed_net_drivers()
{
	net_paths='drivers/net/|doc/guides/nics/features/'
	[ -n "$drivers" ] ||
		drivers=$(changed_files |
			sed -rn "s,^($net_paths)([^./]*).*,\2,p" |
			sort -u)
	echo "$drivers"
}

all_net_drivers()
{
	find $rootdir/drivers/net -mindepth 1 -maxdepth 1 -type d |
	sed 's,.*/,,' |
	sort
}

has_doc_feature() # <ini_file> <feature>
{
	grep -q "^$2[[:space:]]*=[[:space:]]*[YP]" "$1"
}

all_docs_agree() # <driver> <feature>
{
	first=""
	for d in "$rootdir/doc/guides/nics/features/${1}"*.ini; do
		[ -f "$d" ] || return 1
		has_doc_feature "$d" "$2" && val=true || val=false
		[ -n "$first" ] || first=$val
		[ "$first" = "$val" ] || return 1
	done
	return 0
}

check_mq_caps() # <driver>
{
	code=$rootdir/drivers/net/$1
	doc=$rootdir/doc/guides/nics/features/$1.ini
	[ -d $code ] || return 0
	[ -f $doc ] || return 0

	if all_docs_agree $1 "DCB"; then
		if has_doc_feature "$doc" "DCB"; then
			git grep -q '\.get_dcb_info[[:space:]]*=' -- "$code" ||
				error "DCB documented but no get_dcb_info callback for $1"
		else
			! git grep -q '\.get_dcb_info[[:space:]]*=' -- "$code" ||
				error "get_dcb_info callback but DCB not documented for $1"
			! git grep -qE 'RTE_ETH_MQ_(RX|TX).*DCB' -- "$code" ||
				error "DCB mq_mode referenced but DCB not documented for $1"
		fi
	fi

	if all_docs_agree $1 "VMDq"; then
		if has_doc_feature "$doc" "VMDq"; then
			git grep -qE 'max_vmdq_pools[[:space:]]*=' -- "$code" ||
				error "VMDq documented but max_vmdq_pools not set for $1"
		else
			! git grep -qE 'max_vmdq_pools[[:space:]]*=' -- "$code" ||
				error "max_vmdq_pools set but VMDq not documented for $1"
			! git grep -qE 'RTE_ETH_MQ_(RX|TX).*VMDQ' -- "$code" ||
				error "VMDq mq_mode referenced but VMDq not documented for $1"
		fi
	fi
}

check_rte_flow() # <driver>
{
	code=$rootdir/drivers/net/$1
	doc=$rootdir/doc/guides/nics/features/$1.ini
	[ -d $code ] || return 0
	[ -f $doc ] || return 0
	report=$($selfdir/parse-flow-support.sh $code $doc)
	if [ -n "$report" ]; then
		error "rte_flow doc out of sync for $1"
		echo "$report" | sed 's,^,\t,'
	fi
}

if [ -z "$trusted_commit" ]; then
	# check all
	for driver in $(all_net_drivers); do
		check_rte_flow $driver
		check_mq_caps $driver
	done
	exit $result
fi

# find what changed and check
if has_code_change 'RTE_FLOW_.*_TYPE_' ||
		has_file_change 'doc/guides/nics/features'; then
	for driver in $(changed_net_drivers); do
		check_rte_flow $driver
	done
fi
if has_code_change 'get_dcb_info\|max_vmdq_pools\|RTE_ETH_MQ_.*DCB\|RTE_ETH_MQ_.*VMDQ' ||
		has_file_change 'doc/guides/nics/features'; then
	for driver in $(changed_net_drivers); do
		check_mq_caps $driver
	done
fi
exit $result

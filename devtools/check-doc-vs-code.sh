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

net_driver_from_path() # <path>
{
	sed -rn '
		s,.*drivers/net/intel/([^/]*)/.*,\1,p; t
		s,.*drivers/net/([^./]*)/.*,\1,p; t
		s,.*doc/guides/nics/features/([^./]*).*,\1,p'
}

changed_net_drivers()
{
	[ -n "$drivers" ] ||
		drivers=$(changed_files |
			net_driver_from_path |
			sort -u)
	echo "$drivers"
}

all_net_drivers()
{
	{
		find $rootdir/drivers/net -name meson.build
		ls $rootdir/doc/guides/nics/features/*.ini
	} |
	net_driver_from_path |
	sort -u
}

driver_code_dir() # <driver>
{
	drv=$(echo "$1" | sed -r 's/_(dcf|vec|vf)$//')
	case $drv in
	enetc|enetc4)
		echo "$rootdir/drivers/net/enetc" ;;
	igb|igc|e1000)
		echo "$rootdir/drivers/net/intel/e1000" ;;
	ixgbe|i40e|ice|fm10k|ipn3ke|idpf|cpfl|iavf)
		echo "$rootdir/drivers/net/intel/$drv" ;;
	*)
		echo "$rootdir/drivers/net/$drv" ;;
	esac
}

doc_code_map=","
for d in $rootdir/doc/guides/nics/features/*.ini; do
	drv=$(basename "$d" .ini)
	code=$(driver_code_dir $drv)
	case $doc_code_map in
	*,$code:*)
		before=${doc_code_map%,$code:*}
		after=${doc_code_map#*,$code:}
		drivers=${after%%,*}
		rest=${after#*,}
		doc_code_map="$before,$code:$drivers $drv,$rest" ;;
	*)
		doc_code_map="$doc_code_map$code: $drv," ;;
	esac
done

docs_for_code() # <code_dir>
{
	tmp=${doc_code_map#*,$1:}
	echo ${tmp%%,*}
}

# compare doc vs code items:
# - if driver matches code dir: report differences in both directions
# - otherwise: only report doc items not in code (shared code directory)
flow_item_diff() # <driver> <code_dir> <doc_items> <code_items>
{
	{
		[ -n "$3" ] && echo "$3"
		[ -n "$4" ] && {
			echo "$4"
			[ "$1" != $(basename "$2") ] && echo "$4"
		}
	} | sort | uniq -u
}

check_rte_flow() # <driver>
{
	code=$(driver_code_dir $1)
	doc=$rootdir/doc/guides/nics/features/$1.ini
	[ -d $code ] || return 0
	[ -f $doc ] || return 0
	code_support=$($selfdir/parse-flow-support.sh $code)
	report=$(
		for category in item action; do
			section="rte_flow ${category}s]"
			code_items=$(echo "$code_support" | sed -n "/$section/,/]/p" |
				sed '/]/d' | sed 's, *=.*,,' | sed '/^$/d' | sort -u)
			doc_items=$(sed -n "/$section/,/]/p" "$doc" |
				sed '/]/d' | sed 's, *=.*,,' | sed '/^$/d' | sort -u)
			if [ -n "$doc_items" ] || [ -n "$code_items" ]; then
				flow_item_diff $1 $code "$doc_items" "$code_items"
			fi |
			grep . |
			sed "s,^,$category ,"
		done
	)
	if [ -n "$report" ]; then
		error "rte_flow doc out of sync for $1"
		echo "$report" | sed 's,^,\t,'
	fi
}

has_doc_feature() # <ini_file> <feature>
{
	grep -q "^$2[[:space:]]*=[[:space:]]*[YP]" "$1"
}

all_docs_agree() # <driver> <feature>
{
	code=$(driver_code_dir $1)
	first=""
	for drv in $(docs_for_code $code); do
		d=$rootdir/doc/guides/nics/features/$drv.ini
		has_doc_feature "$d" "$2" && val=true || val=false
		[ -n "$first" ] || first=$val
		[ "$first" = "$val" ] || return 1
	done
	return 0
}

check_mq_cap() # <driver> <feature> <indicator> <code_pattern> <mq_pattern>
{
	if all_docs_agree "$1" "$2"; then
		if has_doc_feature "$doc" "$2"; then
			git grep -qE "$4" -- "$code" ||
				error "$2 documented but $3 not set for $1"
		else
			! git grep -qE "$4" -- "$code" ||
				error "$3 set but $2 not documented for $1"
			! git grep -qE "$5" -- "$code" ||
				error "$2 mq_mode referenced but $2 not documented for $1"
		fi
	fi
}

check_mq_caps() # <driver>
{
	code=$(driver_code_dir $1)
	doc=$rootdir/doc/guides/nics/features/$1.ini
	[ -d $code ] || return 0
	[ -f $doc ] || return 0

	check_mq_cap $1 "DCB" "get_dcb_info" '\.get_dcb_info[[:space:]]*=' \
		'RTE_ETH_MQ_(RX|TX).*DCB'
	check_mq_cap $1 "RSS hash" "flow_type_rss_offloads" \
		'flow_type_rss_offloads[[:space:]]*\|?=' 'RTE_ETH_MQ_RX.*RSS'
	check_mq_cap $1 "VMDq" "max_vmdq_pools" 'max_vmdq_pools[[:space:]]*=' \
		'RTE_ETH_MQ_(RX|TX).*VMDQ'
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
if has_code_change 'get_dcb_info|flow_type_rss_offloads|max_vmdq_pools|RTE_ETH_MQ_' ||
		has_file_change 'doc/guides/nics/features'; then
	for driver in $(changed_net_drivers); do
		check_mq_caps $driver
	done
fi
exit $result

#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

if [ "$(uname)" = "Linux" ] ; then
	nr_hugepages=$(cat /proc/sys/vm/nr_hugepages)
	# Need to check if we have permissions to access hugepages
	perm=""
	for mount in `mount | grep hugetlbfs | awk '{ print $3; }'`; do
		test ! -w $mount/. || perm="$mount"
	done
	if [ "$perm" = "" -o "$nr_hugepages" = "0" ]; then
		echo 0
	else
		echo $nr_hugepages
	fi
elif [ "$(uname)" = "FreeBSD" ] ; then
	echo 1 # assume FreeBSD always has hugepages
else
	echo 0
fi

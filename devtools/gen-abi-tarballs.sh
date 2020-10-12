#! /bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

# Generate the required prebuilt ABI references for test-meson-build.sh

# Get arguments
usage() { echo "Usage: $0 [-v <dpdk tag or latest>]" 1>&2; exit 1; }
abi_tag=
while getopts "v:h" arg; do
	case $arg in
	v)
		if [ -n "$DPDK_ABI_REF_VERSION" ]; then
			echo "DPDK_ABI_REF_VERSION and -v cannot both be set"
			exit 1
		fi
		DPDK_ABI_REF_VERSION=${OPTARG} ;;
	h)
		usage ;;
	*)
		usage ;;
	esac
done

if [ -z $DPDK_ABI_REF_VERSION ] ; then
	DPDK_ABI_REF_VERSION="latest"
fi

srcdir=$(dirname $(readlink -f $0))/..

DPDK_ABI_GEN_REF=-20
DPDK_ABI_REF_DIR=$srcdir/__abitarballs

. $srcdir/devtools/test-meson-builds.sh

abirefdir=$DPDK_ABI_REF_DIR/$DPDK_ABI_REF_VERSION

rm -rf $abirefdir/build-*.tar.gz
cd $abirefdir
for f in build-* ; do
	tar -czf $f.tar.gz $f
done
cp *.tar.gz ../
rm -rf *
mv ../*.tar.gz .
rm -rf build-x86-default.tar.gz

echo "The references for $DPDK_ABI_REF_VERSION are now available in $abirefdir"

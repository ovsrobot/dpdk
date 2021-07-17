#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

AS=${AS:-as}
OBJFILE=$(mktemp -t dpdk.binutils-check.XXXXXX)
trap 'rm -f "$OBJFILE"' EXIT

# from https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82887
GCC_VER=6.3.0
gcc --version|grep $GCC_VER && {
    echo "GCC 6.3.0 is broken with  _mm512_extracti64x4_epi64"
    exit 1
}
# from https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90028
GATHER_PARAMS='0x8(,%ymm1,1),%ymm0{%k2}'

# assemble vpgather to file and similarly check
echo "vpgatherqq $GATHER_PARAMS" | $AS --64 -o $OBJFILE -
objdump -d  --no-show-raw-insn $OBJFILE | grep -q $GATHER_PARAMS || {
	echo "vpgatherqq displacement error with as"
	exit 1
}

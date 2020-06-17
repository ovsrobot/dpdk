#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

AS=${AS:-as}
MESON_BUILD_ROOT=${MESON_BUILD_ROOT:-/tmp}
OBJFILE=$MESON_BUILD_ROOT/binutils-avx512-check.o
# from https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90028
GATHER_PARAMS='0x8(,%ymm1,1),%ymm0{%k2}'
# from https://sourceware.org/bugzilla/show_bug.cgi?id=23465
MOVAPS_PARAMS='0x40(,%rax,1),%zmm0'

# assemble vmovaps statement to file
echo "vmovaps $MOVAPS_PARAMS" | $AS --64 -o $OBJFILE -
# check the parameters are correct in the output, using objdump
objdump -d  --no-show-raw-insn $OBJFILE | grep -q $MOVAPS_PARAMS || {
	echo "vmovaps displacement error with as"
	exit 1
}

# assemble vpgather to file and similarly check
echo "vpgatherqq $GATHER_PARAMS" | $AS --64 -o $OBJFILE -
objdump -d  --no-show-raw-insn $OBJFILE | grep -q $GATHER_PARAMS || {
	echo "vpgatherqq displacement error with as"
	exit 1
}

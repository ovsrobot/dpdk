#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation

# wrapper script for cppcheck code analysis tool
# Args:
#   $1: path to scan (optional)

CPPCHECK_BIN=cppcheck
RTE_CONFIG=./build/rte_build_config.h

which $CPPCHECK_BIN > /dev/null 2> /dev/null
if [ $? -ne 0 ]; then
	echo "$CPPCHECK_BIN is missing!" >&2
	exit 1
fi

if [ ! -r $RTE_CONFIG ]; then
	echo "Build not configured missing $RTE_CONFIG" >&2
	exit 1
fi

print_usage () {
	cat <<- END_OF_HELP
	usage: $(basename $0) [-h] [cppcheck options] [file or path]

	Run Linux cppcheck tool with DPDK options.

	END_OF_HELP
}

if [ "$1" = "-h" ]; then
	print_usage
	exit 1;
fi

suppress_args="
	--suppress=invalidPrintfArgType_sint \
	--suppress=invalidPrintfArgType_uint \
	--suppress=duplicateAssignExpression \
	--suppress=nullPointerRedundantCheck \
	--suppress=identicalConditionAfterEarlyExit \
	--suppress=objectIndex \
	--suppress=unknownMacro \
	"

includes="
	--include=$RTE_CONFIG \
	--includes-file=lib/eal/include \
	--includes-file=lib/eal/linux/include \
	"

# all, warning, performance, portability,
# information, unusedFunction, missingInclude
additional_checks=warning

${CPPCHECK_BIN}	--language=c ${includes} \
		--enable=${additional_checks} \
		--force ${suppress_args} $@

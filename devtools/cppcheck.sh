#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation

# wrapper script for cppcheck code analysis tool
# Args:
#   $1: path to scan (optional)

CPPCHECK_BIN=cppcheck
out=cppcheck_error.txt

which ${CPPCHECK_BIN} > /dev/null 2> /dev/null
if [ $? -ne 0 ]; then
	echo "${CPPCHECK_BIN} is missing!"
	exit 1
fi

print_usage () {
	cat <<- END_OF_HELP
	usage: $(basename $0) [-h] [path]

	Wrapper on checkpatch tool. Output goes to ${out} file.

	Without parameter current folder with all subfolders scanned. It is possible
	to provide a sub-folder to recude the scan to that folder.
	END_OF_HELP
}

if [ "$1" = "-h" ]; then
	print_usage
	exit 1;
fi

dir=${1:-$(dirname $(readlink -f $0))/..}
if [ ! -e ${dir} ]; then
	echo "\"${dir}\" is not valid folder/file to check"
	exit 1
fi


suppress_args="
	--suppress=invalidPrintfArgType_sint \
	--suppress=invalidPrintfArgType_uint \
	--suppress=duplicateAssignExpression \
	--suppress=nullPointerRedundantCheck \
	--suppress=identicalConditionAfterEarlyExit \
	--suppress=objectIndex
	"

# all, warning, performance, portability,
# information, unusedFunction, missingInclude
additional_checks=warning

${CPPCHECK_BIN} \
	-j64 \
	--language=c \
	--enable=${additional_checks} \
	--force \
	${suppress_args} \
	${dir} \
	2> ${out}

if [ $? -eq 0 ]; then
	echo -e "\nOutput saved to ${out}"
else
	exit $?
fi

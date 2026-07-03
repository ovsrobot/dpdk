#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Huawei Technologies Co., Ltd
# Run dpdk test with a temporary prefix and clean it up afterwards
set -eEuo pipefail

# Get value of the long option with name in the first argument, from the rest.
get_arg_value() {
	local arg_name="$1"
	shift 1

	local arg_value=''
	local grab_next=false
	local arg

	for arg in "$@"; do
		if $grab_next; then
			arg_value="$arg"
			grab_next=false
		elif [[ "$arg" == "${arg_name}="* ]]; then
			arg_value="${arg#*=}"
		elif [[ "$arg" == "$arg_name" ]]; then
			grab_next=true
		fi
	done

	printf "%s\n" "$arg_value"
}

# Delete work directory passing through the return code
delete_work_directory() {
	local -r test_rc="$1"
	[[ -z "${WORK_DIRECTORY:-}" ]] || rm -rf "$WORK_DIRECTORY"
	return "$test_rc"
}

main() {
	if [[ $# -eq 0 ]]; then
		printf "Usage: %s <test_command> [arguments...]\n" "$0" >&2
		printf "%s %s\n" \
			"Runs a DPDK test with a temporary file prefix" \
			"and cleans up the working directory." >&2
		printf "Ensure the DPDK_TEST environment variable is set.\n" >&2
		exit 1
	fi
	local test_command=("$@")

	if [[ -z "${DPDK_TEST:-}" ]]; then
		printf "Ensure the DPDK_TEST environment variable is set.\n" >&2
		exit 1
	fi
	local -r dpdk_test="$DPDK_TEST"

	# Make sure file prefix is determined and set in test args
	local file_prefix="$(get_arg_value --file-prefix "${test_command[@]}")"
	if [[ -z "$file_prefix" ]]; then
		# If not yet specified, set --file-prefix to test name
		file_prefix="$dpdk_test"
		if [[ -n "$(get_arg_value --trace "${test_command[@]}")" ]]; then
			# Some tests runs twice, with and without traces
			file_prefix="${file_prefix}_with_traces"
		fi
		test_command+=("--file-prefix=$file_prefix")
	fi

	# Make sure runtime directory is determined and set in the environment
	local runtime_directory="${RUNTIME_DIRECTORY:-}"
	if [[ -z "$runtime_directory" ]]; then
		# Follow the algorithm in eal_filesystem.c
		if [[ "$UID" -eq 0 ]]; then
		    runtime_directory='/var/run'
		else
		    runtime_directory="${XDG_RUNTIME_DIR:-/tmp}"
		fi
		export RUNTIME_DIRECTORY="$runtime_directory"
	fi

	WORK_DIRECTORY="$runtime_directory/dpdk/$file_prefix"
	trap 'delete_work_directory "$?"' EXIT

	"${test_command[@]}"
}

main "$@"

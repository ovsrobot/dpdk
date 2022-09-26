#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 University of New Hampshire
#

function get_devtools_dir() {
    dirname "$0"
}

function main() {
    DEVTOOLS_DIR="$(get_devtools_dir)"
    ERRORS=0

    echo "Formatting:"
    env "$DEVTOOLS_DIR/python-format.sh" -c
    ERRORS=$(( ERRORS + $? ))

    echo -ne "\n\n"
    echo "Linting:"
    env "$DEVTOOLS_DIR/python-lint.sh"
    ERRORS=$(( ERRORS + $?))

    exit $ERRORS
}

function usage() {
    echo "Runs all of the dts devtools scripts."
    echo "$0 usage:" && grep -P " \w+\)\ #" "$0"
    exit 0
}

# There shouldn't be any arguments
while getopts "" arg; do
    case $arg in
    *)
    esac
done

main

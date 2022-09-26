#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 University of New Hampshire
#

function main() {
    echo "Running static analysis (linting) using pylama."
    pylama .
    exit $?
}

function usage() {
    echo "Runs pylama, the linter for DTS."
    echo "Exits with a non-zero exit code if there were errors."
    exit 1
}

# There shouldn't be any arguments
while getopts "" arg; do
    case $arg in
    *)
        usage
    esac
done

main

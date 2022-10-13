#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 University of New Hampshire
#

function format() {
    echo "Formatting code with black."
    black .
    echo "Sorting imports with isort."
    isort .
}

function main() {
    format
    exit 0
}

function check_formatting() {
    git update-index --refresh
    retval=$?
    if [[ $retval -ne 0 ]]
    then
        echo 'The "needs update" files have been reformatted.'\
	     'Please update your commit.'
    fi
    exit $retval
}

function usage() {
    echo "Automatically formats dts."
    echo "$0 usage:" && grep -P " \w+\)\ #" $0
    exit 0
}

while getopts "h,c,d:" arg; do
    case $arg in
    h) # Display this message
        usage
        ;;

# Unlike most of these other scripts, format has an argument to control the
# non-zero exit code. This is to allow you to set it as your IDE's formatting
# script, since many IDEs are not compatible with formatting scripts which
# consider changing anything as a failure condition.
    c) # Exit with a non-zero exit code if any files were not properly formatted.
        format
        check_formatting
        ;;
    *)
    esac
done

echo "Running formatting"
main

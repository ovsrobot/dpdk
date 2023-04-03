#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 Stephen Hemminger
#
# This script scans the source tree and creates list of files
# containing words that are recommended to bavoide by the
# Inclusive Naming Initiative.
# See: https://inclusivenaming.org/word-lists/
#
# The options are:
#   -q = quiet mode, produces summary count only
#   -l = show lines instead of files with recommendations
#   -v = verbose, show a header between each tier
#
# Default is to scan all of DPDK source and documentation.
# Optional pathspec can be used to limit specific tree.
#
#  Example:
#    check-naming-policy.sh -q doc/*
#

errors=0
warnings=0
suggestions=0
quiet=false
veborse=false
lines='-l'

print_usage () {
    echo "usage: $(basename $0) [-l] [-q] [-v] [<pathspec>]"
    exit 1
}

# Locate word list files
selfdir=$(dirname $(readlink -f $0))
words=$selfdir/naming

# These give false positives
skipfiles=( ':^devtools/naming/' \
	    ':^doc/guides/rel_notes/' \
	    ':^doc/guides/contributing/coding_style.rst' \
	    ':^doc/guides/prog_guide/glossary.rst' \
)
# These are obsolete
skipfiles+=( \
	    ':^drivers/net/liquidio/' \
	    ':^drivers/net/bnx2x/' \
	    ':^lib/table/' \
	    ':^lib/port/' \
	    ':^lib/pipeline/' \
	    ':^examples/pipeline/' \
)

#
# check_wordlist wordfile description
check_wordlist() {
    local list=$words/$1
    local description=$2

    git grep -i $lines -f $list -- ${skipfiles[@]} $pathspec > $tmpfile
    count=$(wc -l < $tmpfile)
    if ! $quiet; then
	if [ $count -gt 0 ]; then
	    if $verbose; then
   		    echo $description
		    echo $description | tr '[:print:]' '-'
	    fi
   	    cat $tmpfile
	    echo
	fi
    fi
    return $count
}

while getopts lqvh ARG ; do
	case $ARG in
		l ) lines= ;;
		q ) quiet=true ;;
		v ) verbose=true ;;
		h ) print_usage ; exit 0 ;;
		? ) print_usage ; exit 1 ;;
	esac
done
shift $(($OPTIND - 1))

tmpfile=$(mktemp -t dpdk.checknames.XXXXXX)
trap 'rm -f -- "$tmpfile"' INT TERM HUP EXIT

pathspec=$*

check_wordlist tier1.txt "Tier 1: Replace immediately"
errors=$?

check_wordlist tier2.txt "Tier 2: Strongly consider replacing"
warnings=$?

check_wordlist tier3.txt "Tier 3: Recommend to replace"
suggestions=$?

if [ -z "$lines" ] ; then
    echo -n "Total lines: "
else
    echo -n "Total files: "
fi

echo $errors "errors," $warnings "warnings," $suggestions "suggestions"
exit $errors

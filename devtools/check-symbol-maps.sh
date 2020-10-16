#! /bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 Mellanox Technologies, Ltd

cd $(dirname $0)/..

# speed up by ignoring Unicode details
export LC_ALL=C

ret=0

find_orphan_symbols ()
{
    for map in $(find lib drivers -name '*.map') ; do
        for sym in $(sed -rn 's,^([^}]*_.*);,\1,p' $map) ; do
            if echo $sym | grep -q '^per_lcore_' ; then
                symsrc=${sym#per_lcore_}
            elif echo $sym | grep -q '^__rte_.*_trace_' ; then
                symsrc=${sym#__}
            else
                symsrc=$sym
            fi
            if ! grep -q -r --exclude=$(basename $map) \
                    -w $symsrc $(dirname $map) ; then
                echo "$map: $sym"
            fi
        done
    done
}

orphan_symbols=$(find_orphan_symbols)
if [ -n "$orphan_symbols" ] ; then
    echo "Found only in symbol map file:"
    echo "$orphan_symbols" | sed 's,^,\t,'
    ret=1
fi

validate_windows_exports ()
{
    for map in $(find lib drivers -name '*.map') ; do
        def=${map/_version.map}_exports.def
        [ -e $def ] || continue
        for sym in $(grep -v ^EXPORTS $def); do
            grep -q $sym $map || echo $sym
        done
    done
}

unknown_windows_symbols=$(validate_windows_exports)
if [ -n "$unknown_windows_symbols" ] ; then
    echo "Found only in Windows export file:"
    echo "$unknown_windows_symbols" | sed 's,^,\t,'
    ret=1
fi

exit $ret

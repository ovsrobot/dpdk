#!/bin/bash

logdir=/tmp/dpdk_test_mp
repeat=1
lastcore=$(($(nproc) - 1))
log=1

while getopts p:r:lL:d op; do case $op in
    p) lastcore=$OPTARG ;;
    r) repeat=$OPTARG ;;
    L) logdir=$OPTARG ;;
    l) log=0 ;;
    d) debug=1 ;;
esac done
shift $((OPTIND-1))

test=$1
logpath=$logdir/$(date +%y%m%d-%H%M%S)

rm -f core.*
pkill dpdk-test-mp

for j in $(seq $repeat) ; do
    [ $log ] && mkdir -p $logpath/$j
    for i in $(seq 0 $lastcore) ; do
	args="-l $i --file-prefix=dpdk1 --proc-type=auto"
	if [ $debug ] ; then
	    args="$args --log-level=lib.eal:8"
	fi
	if [ $log ] ; then
	    $test $args $lastcore >$logpath/$j/$i.log 2>&1 &
	else
	    $test $args $lastcore &
	fi
    done
    wait || break
    [ $(ls core.* 2>/dev/null | wc -l) -gt 0 ] && break
    echo iteration $j passed
done

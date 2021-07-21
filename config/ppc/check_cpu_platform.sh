#! /bin/sh
LD_SHOW_AUXV=1 /bin/true | awk '/AT_PLATFORM/ {print $2}'|sed  's/\power//'

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

import sys

patch = sys.argv[1]
fn = sys.argv[2]

with open(patch, 'r') as fr:
	fstr = fr.read()

def find_fn_def():
	found = 0
	tmp = 0
	idx = 0
	while found == 0:
		idx = fstr.find("+"+fn+"(", idx)
		if (idx != -1):
			tmp = fstr.find(')', idx)
			if (fstr[tmp + 1] == ';'):
				idx = tmp
				continue
			else:
				found = 1
		else:
			break
	return idx

def find_trace(index):
	fp = fstr.find("{", index)
	sp = fstr.find("}", fp)
	fd = fstr[fp:sp]

	i = fd.find("_trace_")
	if (i != -1):
		return 0
	else:
		return 1


def __main():
	ret=0
	index = find_fn_def()
	if (index != -1):
		# If function definition is present,
		# check if trace call is present
		ret = find_trace(index)
	return ret

if __name__ == "__main__":
	sys.exit(__main())

#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

import random

KEYWORD = 'hello world'
MAX_COUNT = 10
MIN_COUNT = 5
MAX_LEN = 1024
REPEAT_COUNT = random.randrange(MIN_COUNT, MAX_COUNT)

current_pos = 0;
match_pos = []

fd_input = open('input.txt','w')
fd_res = open('res.txt','w')

for i in range(REPEAT_COUNT):
    rand = random.randrange(MAX_LEN)
    fd_input.write(' ' * rand)
    current_pos += rand
    fd_input.write(KEYWORD)
    match_pos.append(current_pos)
    fd_res.write('{}\n'.format(str(current_pos)))
    current_pos += len(KEYWORD)

fd_input.close()
fd_res.close()

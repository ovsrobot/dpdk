# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

drivers = [
        'mlx5',
        'cn9k',
]
std_deps = ['ethdev', 'kvargs', 'regexdev'] # 'ethdev' also pulls in mbuf, net, eal etc

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach

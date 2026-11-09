# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

if not cc.has_header_symbol('linux/if_packet.h', 'PACKET_IGNORE_OUTGOING')
    build = false
    reason = 'missing symbol "PACKET_IGNORE_OUTGOING" in "linux/if_packet.h"'
    subdir_done()
endif

sources = files('rte_eth_af_packet.c')
require_iova_in_mbuf = false

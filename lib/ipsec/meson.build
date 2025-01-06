# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

sources = files('esp_inb.c', 'esp_outb.c',
                'ipsec.c', 'ipsec_group.c', 'ipsec_sad.c',
                'ipsec_telemetry.c', 'sa.c', 'ses.c')

headers = files('rte_ipsec.h', 'rte_ipsec_sa.h', 'rte_ipsec_sad.h')
indirect_headers += files('rte_ipsec_group.h')

deps += ['mbuf', 'net', 'cryptodev', 'security', 'hash', 'telemetry']

annotate_locks = false

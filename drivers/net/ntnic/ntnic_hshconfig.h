/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <flow_api.h>

/* Mapping from dpdk rss hash defines to nt hash defines */
struct nt_eth_rss nt_rss_hash_field_from_dpdk(uint64_t rte_hash_bits);
uint64_t dpdk_rss_hash_define_from_nt_rss(struct nt_eth_rss nt_hsh);

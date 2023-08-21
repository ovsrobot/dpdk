/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <ntlog.h>
#include <flow_api.h>

#include "ntnic_hshconfig.h"

#include <rte_ethdev.h>
#include <nthw_helper.h>

struct pair_uint64_t {
	uint64_t first;
	uint64_t second;
};

#define PAIR_NT(name)                 \
	{                             \
		RTE_##name, NT_##name \
	}

struct pair_uint64_t rte_eth_rss_to_nt[] = {
	PAIR_NT(ETH_RSS_IPV4),
	PAIR_NT(ETH_RSS_FRAG_IPV4),
	PAIR_NT(ETH_RSS_NONFRAG_IPV4_OTHER),
	PAIR_NT(ETH_RSS_IPV6),
	PAIR_NT(ETH_RSS_FRAG_IPV6),
	PAIR_NT(ETH_RSS_NONFRAG_IPV6_OTHER),
	PAIR_NT(ETH_RSS_IPV6_EX),
	PAIR_NT(ETH_RSS_C_VLAN),
	PAIR_NT(ETH_RSS_L3_DST_ONLY),
	PAIR_NT(ETH_RSS_L3_SRC_ONLY),
	PAIR_NT(ETH_RSS_LEVEL_OUTERMOST),
	PAIR_NT(ETH_RSS_LEVEL_INNERMOST),
};

static const uint64_t *rte_to_nt_rss_flag(const uint64_t rte_flag)
{
	const struct pair_uint64_t *start = rte_eth_rss_to_nt;

	for (const struct pair_uint64_t *p = start;
			p != start + ARRAY_SIZE(rte_eth_rss_to_nt); ++p) {
		if (p->first == rte_flag)
			return &p->second;
	}
	return NULL; /* NOT found */
}

static const uint64_t *nt_to_rte_rss_flag(const uint64_t nt_flag)
{
	const struct pair_uint64_t *start = rte_eth_rss_to_nt;

	for (const struct pair_uint64_t *p = start;
			p != start + ARRAY_SIZE(rte_eth_rss_to_nt); ++p) {
		if (p->second == nt_flag)
			return &p->first;
	}
	return NULL; /* NOT found */
}

struct nt_eth_rss nt_rss_hash_field_from_dpdk(uint64_t rte_hash_bits)
{
	struct nt_eth_rss res = { 0 };

	for (uint i = 0; i < sizeof(rte_hash_bits) * CHAR_BIT; ++i) {
		uint64_t rte_bit = (UINT64_C(1) << i);

		if (rte_hash_bits & rte_bit) {
			const uint64_t *nt_bit_p = rte_to_nt_rss_flag(rte_bit);

			if (!nt_bit_p) {
				NT_LOG(ERR, ETHDEV,
				       "RSS hash function field number %d is not supported. Only supported fields will be used in RSS hash function.",
				       i);
			} else {
				res.fields |= *nt_bit_p;
			}
		}
	}

	return res;
}

uint64_t dpdk_rss_hash_define_from_nt_rss(struct nt_eth_rss nt_hsh)
{
	uint64_t res = 0;

	for (uint i = 0; i < sizeof(nt_hsh.fields) * CHAR_BIT; ++i) {
		uint64_t nt_bit = (UINT64_C(1) << i);

		if (nt_hsh.fields & nt_bit) {
			const uint64_t *rte_bit_p = nt_to_rte_rss_flag(nt_bit);

			assert(rte_bit_p &&
			       "All nt rss bit flags should be mapped to rte rss bit fields, as nt rss is a subset of rte options");
			res |= *rte_bit_p;
		}
	}

	return res;
}

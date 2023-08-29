/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTNIC_XSTATS_H_
#define NTNIC_XSTATS_H_

int nthw_xstats_get_names(nt4ga_stat_t *p_nt4ga_stat,
			  struct rte_eth_xstat_name *xstats_names,
			  unsigned int size, bool is_vswitch);
int nthw_xstats_get(nt4ga_stat_t *p_nt4ga_stat, struct rte_eth_xstat *stats,
		    unsigned int n, bool is_vswitch, uint8_t port);
void nthw_xstats_reset(nt4ga_stat_t *p_nt4ga_stat, bool is_vswitch, uint8_t port);
int nthw_xstats_get_names_by_id(nt4ga_stat_t *p_nt4ga_stat,
				struct rte_eth_xstat_name *xstats_names,
				const uint64_t *ids, unsigned int size,
				bool is_vswitch);
int nthw_xstats_get_by_id(nt4ga_stat_t *p_nt4ga_stat, const uint64_t *ids,
			  uint64_t *values, unsigned int n, bool is_vswitch,
			  uint8_t port);

#endif /* NTNIC_XSTATS_H_ */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NT4GA_PCI_TA_TG_H_
#define _NT4GA_PCI_TA_TG_H_

#include <stdint.h>

#define TA_TG_DBG_SHOW_SUMMARY (1)

#define TG_NUM_PACKETS (8)
#define TG_PKT_SIZE (2048 * 1)
#define TG_AREA_SIZE (TG_NUM_PACKETS * TG_PKT_SIZE)

#define TG_DELAY (200000)	/* usec */

/* Struct predefinitions */
struct adapter_info_s;
struct nthw_hif_end_point_counters;

struct nt4ga_pci_ta_tg_s {
	struct nthw_pci_rd_tg *mp_nthw_pci_rd_tg;
	struct nthw_pci_wr_tg *mp_nthw_pci_wr_tg;
	struct nthw_pci_ta *mp_nthw_pci_ta;
};

typedef struct nt4ga_pci_ta_tg_s nt4ga_pci_ta_tg_t;
typedef struct nt4ga_pci_ta_tg_s nt4ga_pci_ta_tg;

int nt4ga_pci_ta_tg_init(struct adapter_info_s *p_adapter_info);

int nt4ga_pci_ta_tg_measure_throughput_run(struct adapter_info_s *p_adapter_info,
	struct nthw_hif_end_point_counters *pri,
	struct nthw_hif_end_point_counters *sla);
int nt4ga_pci_ta_tg_measure_throughput_main(struct adapter_info_s *p_adapter_info,
	const uint8_t numa_node, const int direction,
	const int n_pkt_size, const int n_batch_count,
	const int n_delay);

#endif	/* _NT4GA_PCI_TA_TG_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef _NITROX_CSR_H_
#define _NITROX_CSR_H_

#include <rte_common.h>
#include <rte_io.h>

#define CSR_DELAY	30
#define NITROX_CSR_ADDR(bar_addr, offset) (bar_addr + (offset))

/* NPS packet registers */
#define NPS_PKT_IN_INSTR_CTLX(_i)	(0x10060 + ((_i) * 0x40000))
#define NPS_PKT_IN_INSTR_BADDRX(_i)	(0x10068 + ((_i) * 0x40000))
#define NPS_PKT_IN_INSTR_RSIZEX(_i)	(0x10070 + ((_i) * 0x40000))
#define NPS_PKT_IN_DONE_CNTSX(_i)	(0x10080 + ((_i) * 0x40000))
#define NPS_PKT_IN_INSTR_BAOFF_DBELLX(_i)	(0x10078 + ((_i) * 0x40000))
#define NPS_PKT_IN_INT_LEVELSX(_i)		(0x10088 + ((_i) * 0x40000))
#define NPS_PKT_SLC_CTLX(_i)		(0x10000 + ((_i) * 0x40000))
#define NPS_PKT_SLC_CNTSX(_i)		(0x10008 + ((_i) * 0x40000))
#define NPS_PKT_SLC_INT_LEVELSX(_i)	(0x10010 + ((_i) * 0x40000))

/* AQM Virtual Function Registers */
#define AQMQ_QSZX(_i)			(0x20008 + ((_i)*0x40000))

static inline uint64_t
nitrox_read_csr(uint8_t *bar_addr, uint64_t offset)
{
	return rte_read64(bar_addr + offset);
}

static inline void
nitrox_write_csr(uint8_t *bar_addr, uint64_t offset, uint64_t value)
{
	rte_write64(value, (bar_addr + offset));
}

#endif /* _NITROX_CSR_H_ */

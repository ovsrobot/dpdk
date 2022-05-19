/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _HE_LBK_H_
#define _HE_LBK_H_

#include "afu_mf_rawdev.h"
#include "rte_pmd_afu.h"

#define HE_LBK_UUID_L      0xb94b12284c31e02b
#define HE_LBK_UUID_H      0x56e203e9864f49a7
#define HE_MEM_LBK_UUID_L  0xbb652a578330a8eb
#define HE_MEM_LBK_UUID_H  0x8568ab4e6ba54616

extern struct afu_mf_drv he_lbk_drv;
extern struct afu_mf_drv he_mem_lbk_drv;

/* HE-LBK & HE-MEM-LBK registers definition */
#define CSR_SCRATCHPAD0    0x100
#define CSR_SCRATCHPAD1    0x108
#define CSR_AFU_DSM_BASEL  0x110
#define CSR_AFU_DSM_BASEH  0x114
#define CSR_SRC_ADDR       0x120
#define CSR_DST_ADDR       0x128
#define CSR_NUM_LINES      0x130
#define CSR_CTL            0x138
#define CSR_CFG            0x140
#define CSR_INACT_THRESH   0x148
#define CSR_INTERRUPT0     0x150
#define CSR_SWTEST_MSG     0x158
#define CSR_STATUS0        0x160
#define CSR_STATUS1        0x168
#define CSR_ERROR          0x170
#define CSR_STRIDE         0x178
#define CSR_HE_INFO0       0x180

#define DSM_SIZE           0x200000
#define DSM_POLL_INTERVAL  5  /* ms */
#define DSM_TIMEOUT        1000  /* ms */

#define NLB_BUF_SIZE  0x400000
#define TEST_MEM_ALIGN  1024

struct he_lbk_csr_ctl {
	union {
		uint32_t csr;
		struct {
			uint32_t reset:1;
			uint32_t start:1;
			uint32_t force_completion:1;
			uint32_t reserved:29;
		};
	};
};

struct he_lbk_csr_cfg {
	union {
		uint32_t csr;
		struct {
			uint32_t rsvd1:1;
			uint32_t cont:1;
			uint32_t mode:3;
			uint32_t multicl_len:2;
			uint32_t rsvd2:13;
			uint32_t trput_interleave:3;
			uint32_t test_cfg:5;
			uint32_t interrupt_on_error:1;
			uint32_t interrupt_testmode:1;
			uint32_t rsvd3:2;
		};
	};
};

struct he_lbk_status0 {
	union {
		uint64_t csr;
		struct {
			uint32_t num_writes;
			uint32_t num_reads;
		};
	};
};

struct he_lbk_status1 {
	union {
		uint64_t csr;
		struct {
			uint32_t num_pend_writes;
			uint32_t num_pend_reads;
		};
	};
};

struct he_lbk_dsm_status {
	uint32_t test_complete;
	uint32_t test_error;
	uint64_t num_clocks;
	uint32_t num_reads;
	uint32_t num_writes;
	uint32_t start_overhead;
	uint32_t end_overhead;
};

struct he_lbk_ctx {
	uint8_t *addr;
	uint8_t *dsm_ptr;
	uint64_t dsm_iova;
	uint8_t *src_ptr;
	uint64_t src_iova;
	uint8_t *dest_ptr;
	uint64_t dest_iova;
	struct he_lbk_dsm_status *status_ptr;
};

struct he_lbk_priv {
	struct rte_pmd_afu_he_lbk_cfg he_lbk_cfg;
	struct he_lbk_ctx he_lbk_ctx;
};

#endif /* _HE_LBK_H_ */

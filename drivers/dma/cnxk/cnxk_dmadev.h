/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell International Ltd.
 */
#ifndef _CNXK_DMADEV_H_
#define _CNXK_DMADEV_H_

#define DPI_MAX_POINTER		15
#define DPI_QUEUE_STOP		0x0
#define DPI_QUEUE_START		0x1
#define STRM_INC(s)		((s).tail = ((s).tail + 1) % (s).max_cnt)
#define DPI_MAX_DESC		DPI_MAX_POINTER

/* DPI Transfer Type, pointer type in DPI_DMA_INSTR_HDR_S[XTYPE] */
#define DPI_XTYPE_OUTBOUND      (0)
#define DPI_XTYPE_INBOUND       (1)
#define DPI_XTYPE_INTERNAL_ONLY (2)
#define DPI_XTYPE_EXTERNAL_ONLY (3)
#define DPI_XTYPE_MASK		0x3
#define DPI_HDR_PT_ZBW_CA	0x0
#define DPI_HDR_PT_ZBW_NC	0x1
#define DPI_HDR_PT_WQP		0x2
#define DPI_HDR_PT_WQP_NOSTATUS	0x0
#define DPI_HDR_PT_WQP_STATUSCA	0x1
#define DPI_HDR_PT_WQP_STATUSNC	0x3
#define DPI_HDR_PT_CNT		0x3
#define DPI_HDR_PT_MASK		0x3
#define DPI_W0_TT_MASK		0x3
#define DPI_W0_GRP_MASK		0x3FF

/* Set Completion data to 0xFF when request submitted,
 * upon successful request completion engine reset to completion status
 */
#define DPI_REQ_CDATA		0xFF

#define DPI_MIN_CMD_SIZE	8
#define DPI_MAX_CMD_SIZE	64

struct cnxk_dpi_compl_s {
	uint64_t cdata;
	void *cb_data;
};

struct cnxk_dpi_cdesc_data_s {
	struct cnxk_dpi_compl_s *compl_ptr[DPI_MAX_DESC];
	uint16_t max_cnt;
	uint16_t head;
	uint16_t tail;
};

struct cnxk_dpi_queue_conf {
	uint8_t direction;
	uint8_t src_port;
	uint8_t dst_port;
	uint64_t comp_ptr;
	struct cnxk_dpi_cdesc_data_s c_desc;
};

struct cnxk_dpi_vf_s {
	struct roc_dpi rdpi;
	struct cnxk_dpi_queue_conf conf;
	uint32_t num_words;
};

#endif

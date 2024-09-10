/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_COMMON_H_
#define _ZSDA_COMMON_H_

#include <stdint.h>

#include <rte_bus_pci.h>
#include <rte_mbuf.h>
#include <rte_io.h>

#include "zsda_logs.h"

#define ZSDA_DEV_NAME_MAX_LEN 64
#define MAX_QPS_ON_FUNCTION   128

#define ADMIN_WQ_BASE_ADDR_0 0x40
#define ADMIN_WQ_BASE_ADDR_1 0x44
#define ADMIN_WQ_BASE_ADDR_2 0x48
#define ADMIN_WQ_BASE_ADDR_3 0x4C
#define ADMIN_WQ_BASE_ADDR_4 0x50
#define ADMIN_WQ_BASE_ADDR_5 0x54
#define ADMIN_WQ_BASE_ADDR_6 0x58
#define ADMIN_WQ_BASE_ADDR_7 0x5C

#define ADMIN_CQ_BASE_ADDR_0 0x60
#define ADMIN_CQ_BASE_ADDR_1 0x64
#define ADMIN_CQ_BASE_ADDR_2 0x68
#define ADMIN_CQ_BASE_ADDR_3 0x6C
#define ADMIN_CQ_BASE_ADDR_4 0x70
#define ADMIN_CQ_BASE_ADDR_5 0x74
#define ADMIN_CQ_BASE_ADDR_6 0x78
#define ADMIN_CQ_BASE_ADDR_7 0x7C

#define IO_DB_INITIAL_CONFIG 0x1C00

#define ADMIN_BUF_DATA_LEN  0x1C
#define ADMIN_BUF_TOTAL_LEN 0x20

#define ZSDA_CSR_VERSION      0x0
#define ZSDA_ADMIN_WQ	      0x40
#define ZSDA_ADMIN_WQ_BASE7   0x5C
#define ZSDA_ADMIN_WQ_CRC     0x5C
#define ZSDA_ADMIN_WQ_VERSION 0x5D
#define ZSDA_ADMIN_WQ_FLAG    0x5E
#define ZSDA_ADMIN_CQ	      0x60
#define ZSDA_ADMIN_CQ_BASE7   0x7C
#define ZSDA_ADMIN_CQ_CRC     0x7C
#define ZSDA_ADMIN_CQ_VERSION 0x7D
#define ZSDA_ADMIN_CQ_FLAG    0x7E

#define ZSDA_ADMIN_WQ_TAIL 0x80
#define ZSDA_ADMIN_CQ_HEAD 0x84

#define ZSDA_ADMIN_Q_START     0x100
#define ZSDA_ADMIN_Q_STOP      0x100
#define ZSDA_ADMIN_Q_STOP_RESP 0x104
#define ZSDA_ADMIN_Q_CLR       0x108
#define ZSDA_ADMIN_Q_CLR_RESP  0x10C

#define ZSDA_IO_Q_START	    0x200
#define ZSDA_IO_Q_STOP	    0x200
#define ZSDA_IO_Q_STOP_RESP 0x400
#define ZSDA_IO_Q_CLR	    0x600
#define ZSDA_IO_Q_CLR_RESP  0x800

#define ZSDA_CSR_READ32(addr)	      rte_read32((addr))
#define ZSDA_CSR_WRITE32(addr, value) rte_write32((value), (addr))
#define ZSDA_CSR_READ16(addr)	      rte_read16((addr))
#define ZSDA_CSR_WRITE16(addr, value) rte_write16((value), (addr))
#define ZSDA_CSR_READ8(addr)	      rte_read8((addr))
#define ZSDA_CSR_WRITE8(addr, value)  rte_write8_relaxed((value), (addr))

#define ZSDA_PCI_NAME	        zsda
#define ZSDA_SGL_MAX_NUMBER     512
#define ZSDA_SGL_FRAGMENT_SIZE  32
#define NB_DES		       512

#define ZSDA_SUCCESS EXIT_SUCCESS
#define ZSDA_FAILED  (-1)

#define E_NULL	  "Failed! Addr is NULL"
#define E_CREATE  "Failed! Create"
#define E_FUNC	  "Failed! Function"
#define E_START_Q "Failed! START q"
#define E_MALLOC  "Failed! malloc"
#define E_FREE	  "Failed! free"

#define E_COMPARE "Failed! compare"
#define E_START	  "Failed! start/setup"
#define E_CLOSE	  "Failed! stop/close"
#define E_CONFIG  "Failed! config"
#define E_RESULT  "Failed! result wrong"

enum zsda_service_type {
	ZSDA_SERVICE_COMPRESSION = 0,
	ZSDA_SERVICE_DECOMPRESSION,
	ZSDA_SERVICE_INVALID,
};

#define ZSDA_MAX_SERVICES (ZSDA_SERVICE_INVALID)

#define ZSDA_OPC_COMP_GZIP	0x10 /* Encomp deflate-Gzip */
#define ZSDA_OPC_COMP_ZLIB	0x11 /* Encomp deflate-Zlib */
#define ZSDA_OPC_DECOMP_GZIP	0x18 /* Decompinfalte-Gzip */
#define ZSDA_OPC_DECOMP_ZLIB	0x19 /* Decompinfalte-Zlib */
#define ZSDA_OPC_INVALID	0xff

#define SET_CYCLE	  0xff
#define SET_HEAD_INTI	  0x0

#define ZSDA_Q_START	   0x1
#define ZSDA_Q_STOP	   0x0
#define ZSDA_CLEAR_VALID   0x1
#define ZSDA_CLEAR_INVALID 0x0
#define ZSDA_RESP_VALID	   0x1
#define ZSDA_RESP_INVALID  0x0

#define ZSDA_TIME_SLEEP_US 100
#define ZSDA_TIME_NUM 500

#define ZSDA_MAX_DESC 512
#define ZSDA_MAX_CYCLE 256
#define ZSDA_MAX_DEV 256
#define MAX_NUM_OPS   0x1FF

struct zsda_pci_device;

enum sgl_element_type_wqe {
	SGL_ELM_TYPE_PHYS_ADDR = 1,
	SGL_ELM_TYPE_LIST,
	SGL_ELM_TYPE_LIST_ADDR,
	SGL_ELM_TYPE_LIST_SGL32,
};

enum sgl_element_type {
	SGL_TYPE_PHYS_ADDR = 0,
	SGL_TYPE_LAST_PHYS_ADDR,
	SGL_TYPE_NEXT_LIST,
	SGL_TYPE_EC_LEVEL1_SGL32,
};

enum zsda_admin_msg_id {
	/* Version information */
	ZSDA_ADMIN_VERSION_REQ = 0,
	ZSDA_ADMIN_VERSION_RESP,
	/* algo type */
	ZSDA_ADMIN_QUEUE_CFG_REQ,
	ZSDA_ADMIN_QUEUE_CFG_RESP,
	/* get cycle */
	ZSDA_ADMIN_QUEUE_CYCLE_REQ,
	ZSDA_ADMIN_QUEUE_CYCLE_RESP,
	/* set cyclr */
	ZSDA_ADMIN_SET_CYCLE_REQ,
	ZSDA_ADMIN_SET_CYCLE_RESP,

	ZSDA_MIG_STATE_WARNING,
	ZSDA_ADMIN_RESERVE,
	/* set close flr register */
	ZSDA_FLR_SET_FUNCTION,
	ZSDA_ADMIN_MSG_VALID,
	ZSDA_ADMIN_INT_TEST
};

struct zsda_admin_req {
	uint16_t msg_type;
	uint8_t data[26];
};

struct zsda_admin_resp {
	uint16_t msg_type;
	uint8_t data[26];
};

struct zsda_test_msg {
	uint32_t msg_type;
	uint32_t data_in;
	uint8_t data[20];
};

struct zsda_admin_req_qcfg {
	uint16_t msg_type;
	uint8_t qid;
	uint8_t data[25];
};

#pragma pack(1)
struct qinfo {
	uint16_t q_type;
	uint16_t wq_tail;
	uint16_t wq_head;
	uint16_t cq_tail;
	uint16_t cq_head;
	uint16_t cycle;
};

struct zsda_admin_resp_qcfg {
	uint16_t msg_type;
	struct qinfo qcfg;
	uint8_t data[14];
};
#pragma pack()

enum flr_clr_mask {
	unmask = 0,
	mask,
};

/**< Common struct for scatter-gather list operations */
struct zsda_buf {
	uint64_t addr;
	uint32_t len;
	uint8_t resrvd[3];
	uint8_t type;
} __rte_packed;

struct __rte_cache_aligned zsda_sgl {
	struct zsda_buf buffers[ZSDA_SGL_MAX_NUMBER];
};

/* The space length. The space is used for compression header and tail */
#define COMP_REMOVE_SPACE_LEN 16

struct zsda_op_cookie {
	bool used;
	bool decomp_no_tail;
	void *op;
	uint16_t sid;
	struct zsda_sgl sgl_src;
	struct zsda_sgl sgl_dst;
	phys_addr_t sgl_src_phys_addr;
	phys_addr_t sgl_dst_phys_addr;
	phys_addr_t comp_head_phys_addr;

	uint8_t comp_head[COMP_REMOVE_SPACE_LEN];
} __rte_packed;

struct compress_cfg {
} __rte_packed;

struct zsda_wqe_comp {
	uint8_t valid;
	uint8_t op_code;
	uint16_t sid;
	uint8_t resv[3];
	uint8_t rx_sgl_type : 4;
	uint8_t tx_sgl_type : 4;
	uint64_t rx_addr;
	uint32_t rx_length;
	uint64_t tx_addr;
	uint32_t tx_length;
	struct compress_cfg cfg;
} __rte_packed;

struct zsda_cqe {
	uint8_t valid; /* cqe_cycle */
	uint8_t op_code;
	uint16_t sid;
	uint8_t state;
	uint8_t result;
	uint16_t zsda_wq_id;
	uint32_t tx_real_length;
	uint16_t err0;
	uint16_t err1;
} __rte_packed;

struct zsda_common_stat {
	/**< Count of all operations enqueued */
	uint64_t enqueued_count;
	/**< Count of all operations dequeued */
	uint64_t dequeued_count;

	/**< Total error count on operations enqueued */
	uint64_t enqueue_err_count;
	/**< Total error count on operations dequeued */
	uint64_t dequeue_err_count;
};

enum zsda_algo_core {
	ZSDA_CORE_COMP,
	ZSDA_CORE_DECOMP,
	ZSDA_CORE_INVALID,
};

static inline uint32_t
zsda_modulo_32(uint32_t data, uint32_t modulo_mask)
{
	return (data) & (modulo_mask);
}
static inline uint16_t
zsda_modulo_16(uint16_t data, uint16_t modulo_mask)
{
	return (data) & (modulo_mask);
}
static inline uint8_t
zsda_modulo_8(uint8_t data, uint8_t modulo_mask)
{
	return (data) & (modulo_mask);
}

#define CQE_VALID(value) (value & 0x8000)
#define CQE_ERR0(value) (value & 0xffff)
#define CQE_ERR1(value) (value & 0x7fff)

/* For situations where err0 are reported but the results are correct */
#define DECOMP_RIGHT_ERR0_0 0xc710
#define DECOMP_RIGHT_ERR0_1 0xc727
#define DECOMP_RIGHT_ERR0_2 0xc729
#define CQE_ERR0_RIGHT(value)                                                  \
	(value == DECOMP_RIGHT_ERR0_0 || value == DECOMP_RIGHT_ERR0_1 ||       \
	 value == DECOMP_RIGHT_ERR0_2)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

uint32_t zsda_set_reg_8(void *addr, const uint8_t val0, const uint8_t val1,
		   const uint8_t val2, const uint8_t val3);
uint8_t zsda_get_reg_8(void *addr, const int offset);

int zsda_admin_msg_init(const struct rte_pci_device *pci_dev);
int zsda_send_admin_msg(const struct rte_pci_device *pci_dev, void *req,
			const uint32_t len);

int zsda_recv_admin_msg(const struct rte_pci_device *pci_dev, void *resp,
			const uint32_t len);

#endif /* _ZSDA_COMMON_H_ */

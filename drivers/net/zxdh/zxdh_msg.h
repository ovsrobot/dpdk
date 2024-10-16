/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_MSG_H_
#define _ZXDH_MSG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <ethdev_driver.h>

#define ZXDH_BAR0_INDEX          0

#define ZXDH_CTRLCH_OFFSET          (0x2000)
#define ZXDH_MSG_CHAN_PFVFSHARE_OFFSET  (ZXDH_CTRLCH_OFFSET + 0x1000)
#define ZXDH_MSIX_INTR_MSG_VEC_BASE  1

#define ZXDH_MSIX_INTR_MSG_VEC_NUM  3
#define ZXDH_MSIX_INTR_DTB_VEC      (ZXDH_MSIX_INTR_MSG_VEC_BASE + ZXDH_MSIX_INTR_MSG_VEC_NUM)
#define ZXDH_MSIX_INTR_DTB_VEC_NUM  1
#define ZXDH_INTR_NONQUE_NUM        (ZXDH_MSIX_INTR_MSG_VEC_NUM + ZXDH_MSIX_INTR_DTB_VEC_NUM + 1)
#define ZXDH_QUEUE_INTR_VEC_BASE    (ZXDH_MSIX_INTR_DTB_VEC + ZXDH_MSIX_INTR_DTB_VEC_NUM) /* 5 */
#define ZXDH_QUEUE_INTR_VEC_NUM     256

#define BAR_MSG_POLLING_SPAN     100
#define BAR_MSG_POLL_CNT_PER_MS  (1 * 1000 / BAR_MSG_POLLING_SPAN)
#define BAR_MSG_POLL_CNT_PER_S   (1 * 1000 * 1000 / BAR_MSG_POLLING_SPAN)
#define BAR_MSG_TIMEOUT_TH       (10 * 1000 * 1000 / BAR_MSG_POLLING_SPAN)

#define BAR_CHAN_MSG_SYNC     0

#define BAR_MSG_ADDR_CHAN_INTERVAL  (2 * 1024) /* channel size */
#define BAR_MSG_PLAYLOAD_OFFSET     (sizeof(struct bar_msg_header))
#define BAR_MSG_PAYLOAD_MAX_LEN     (BAR_MSG_ADDR_CHAN_INTERVAL - sizeof(struct bar_msg_header))

enum DRIVER_TYPE {
	MSG_CHAN_END_MPF = 0,
	MSG_CHAN_END_PF,
	MSG_CHAN_END_VF,
	MSG_CHAN_END_RISC,
};

enum MSG_VEC {
	MSIX_FROM_PFVF = ZXDH_MSIX_INTR_MSG_VEC_BASE,
	MSIX_FROM_MPF,
	MSIX_FROM_RISCV,
	MSG_VEC_NUM,
};

enum BAR_MSG_RTN {
	BAR_MSG_OK = 0,
	BAR_MSG_ERR_MSGID,
	BAR_MSG_ERR_NULL,
	BAR_MSG_ERR_TYPE, /* Message type exception */
	BAR_MSG_ERR_MODULE, /* Module ID exception */
	BAR_MSG_ERR_BODY_NULL, /* Message body exception */
	BAR_MSG_ERR_LEN, /* Message length exception */
	BAR_MSG_ERR_TIME_OUT, /* Message sending length too long */
	BAR_MSG_ERR_NOT_READY, /* Abnormal message sending conditions*/
	BAR_MEG_ERR_NULL_FUNC, /* Empty receive processing function pointer*/
	BAR_MSG_ERR_REPEAT_REGISTER, /* Module duplicate registration*/
	BAR_MSG_ERR_UNGISTER, /* Repeated deregistration*/
	/**
	 * The sending interface parameter boundary structure pointer is empty
	 */
	BAR_MSG_ERR_NULL_PARA,
	BAR_MSG_ERR_REPSBUFF_LEN, /* The length of reps_buff is too short*/
	/**
	 * Unable to find the corresponding message processing function for this module
	 */
	BAR_MSG_ERR_MODULE_NOEXIST,
	/**
	 * The virtual address in the parameters passed in by the sending interface is empty
	 */
	BAR_MSG_ERR_VIRTADDR_NULL,
	BAR_MSG_ERR_REPLY, /* sync msg resp_error */
	BAR_MSG_ERR_MPF_NOT_SCANNED,
	BAR_MSG_ERR_KERNEL_READY,
	BAR_MSG_ERR_USR_RET_ERR,
	BAR_MSG_ERR_ERR_PCIEID,
	BAR_MSG_ERR_SOCKET, /* netlink sockte err */
};

enum bar_module_id {
	BAR_MODULE_DBG = 0, /* 0:  debug */
	BAR_MODULE_TBL,     /* 1:  resource table */
	BAR_MODULE_MISX,    /* 2:  config msix */
	BAR_MODULE_SDA,     /* 3: */
	BAR_MODULE_RDMA,    /* 4: */
	BAR_MODULE_DEMO,    /* 5:  channel test */
	BAR_MODULE_SMMU,    /* 6: */
	BAR_MODULE_MAC,     /* 7:  mac rx/tx stats */
	BAR_MODULE_VDPA,    /* 8:  vdpa live migration */
	BAR_MODULE_VQM,     /* 9:  vqm live migration */
	BAR_MODULE_NP,      /* 10: vf msg callback np */
	BAR_MODULE_VPORT,   /* 11: get vport */
	BAR_MODULE_BDF,     /* 12: get bdf */
	BAR_MODULE_RISC_READY, /* 13: */
	BAR_MODULE_REVERSE,    /* 14: byte stream reverse */
	BAR_MDOULE_NVME,       /* 15: */
	BAR_MDOULE_NPSDK,      /* 16: */
	BAR_MODULE_NP_TODO,    /* 17: */
	MODULE_BAR_MSG_TO_PF,  /* 18: */
	MODULE_BAR_MSG_TO_VF,  /* 19: */

	MODULE_FLASH = 32,
	BAR_MODULE_OFFSET_GET = 33,
	BAR_EVENT_OVS_WITH_VCB = 36,

	BAR_MSG_MODULE_NUM = 100,
};

enum RES_TBL_FILED {
	TBL_FIELD_PCIEID     = 0,
	TBL_FIELD_BDF        = 1,
	TBL_FIELD_MSGCH      = 2,
	TBL_FIELD_DATACH     = 3,
	TBL_FIELD_VPORT      = 4,
	TBL_FIELD_PNLID      = 5,
	TBL_FIELD_PHYPORT    = 6,
	TBL_FIELD_SERDES_NUM = 7,
	TBL_FIELD_NP_PORT    = 8,
	TBL_FIELD_SPEED      = 9,
	TBL_FIELD_HASHID     = 10,
	TBL_FIELD_NON,
};

enum TBL_MSG_TYPE {
	TBL_TYPE_READ,
	TBL_TYPE_WRITE,
	TBL_TYPE_NON,
};

struct msix_para {
	uint16_t pcie_id;
	uint16_t vector_risc;
	uint16_t vector_pfvf;
	uint16_t vector_mpf;
	uint64_t virt_addr;
	uint16_t driver_type; /* refer to DRIVER_TYPE */
};

struct msix_msg {
	uint16_t pcie_id;
	uint16_t vector_risc;
	uint16_t vector_pfvf;
	uint16_t vector_mpf;
};

struct zxdh_pci_bar_msg {
	uint64_t virt_addr; /* bar addr */
	void    *payload_addr;
	uint16_t payload_len;
	uint16_t emec;
	uint16_t src; /* refer to BAR_DRIVER_TYPE */
	uint16_t dst; /* refer to BAR_DRIVER_TYPE */
	uint16_t module_id;
	uint16_t src_pcieid;
	uint16_t dst_pcieid;
	uint16_t usr;
};

struct bar_msix_reps {
	uint16_t pcie_id;
	uint16_t check;
	uint16_t vport;
	uint16_t rsv;
} __rte_packed;

struct bar_offset_reps {
	uint16_t check;
	uint16_t rsv;
	uint32_t offset;
	uint32_t length;
} __rte_packed;

struct bar_recv_msg {
	uint8_t reps_ok;
	uint16_t reps_len;
	uint8_t rsv;
	/* */
	union {
		struct bar_msix_reps msix_reps;
		struct bar_offset_reps offset_reps;
	} __rte_packed;
} __rte_packed;

struct zxdh_msg_recviver_mem {
	void *recv_buffer; /* first 4B is head, followed by payload */
	uint64_t buffer_len;
};

struct bar_msg_header {
	uint8_t valid : 1; /* used by __bar_chan_msg_valid_set/get */
	uint8_t sync  : 1;
	uint8_t emec  : 1; /* emergency? */
	uint8_t ack   : 1; /* ack msg? */
	uint8_t poll  : 1;
	uint8_t usr   : 1;
	uint8_t rsv;
	uint16_t module_id;
	uint16_t len;
	uint16_t msg_id;
	uint16_t src_pcieid;
	uint16_t dst_pcieid; /* used in PF-->VF */
};

typedef int (*zxdh_bar_chan_msg_recv_callback)(void *pay_load, uint16_t len,
					void *reps_buffer, uint16_t *reps_len, void *dev);

int zxdh_msg_chan_init(void);
int zxdh_bar_msg_chan_exit(void);
int zxdh_msg_chan_hwlock_init(struct rte_eth_dev *dev);

int zxdh_msg_chan_enable(struct rte_eth_dev *dev);
int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in,
			struct zxdh_msg_recviver_mem *result);
int zxdh_bar_irq_recv(uint8_t src, uint8_t dst, uint64_t virt_addr, void *dev);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_MSG_H_  */

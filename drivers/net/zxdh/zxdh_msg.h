/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#ifndef _ZXDH_MSG_CHAN_H_
#define _ZXDH_MSG_CHAN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define ZXDH_MSG_CHAN_PFVFSHARE_OFFSET  (ZXDH_CTRLCH_OFFSET + 0x1000)
#define ZXDH_MSIX_INTR_MSG_VEC_BASE  1
#define ZXDH_MSIX_INTR_MSG_VEC_NUM   3

#define BAR_MSG_POLLING_SPAN     100 /* sleep us */
#define BAR_MSG_POLL_CNT_PER_MS  (1 * 1000 / BAR_MSG_POLLING_SPAN)
#define BAR_MSG_POLL_CNT_PER_S   (1 * 1000 * 1000 / BAR_MSG_POLLING_SPAN)
#define BAR_MSG_TIMEOUT_TH       (10 * 1000 * 1000 / BAR_MSG_POLLING_SPAN) /* 10s */

#define BAR_CHAN_MSG_SYNC     0
#define BAR_CHAN_MSG_ASYNC    1
#define BAR_CHAN_MSG_NO_EMEC  0
#define BAR_CHAN_MSG_EMEC     1
#define BAR_CHAN_MSG_NO_ACK   0
#define BAR_CHAN_MSG_ACK      1

#define ZXDH_MSIX_INTR_DTB_VEC      (ZXDH_MSIX_INTR_MSG_VEC_BASE + ZXDH_MSIX_INTR_MSG_VEC_NUM)
#define ZXDH_MSIX_INTR_DTB_VEC_NUM  1
#define ZXDH_INTR_NONQUE_NUM        (ZXDH_MSIX_INTR_MSG_VEC_NUM + ZXDH_MSIX_INTR_DTB_VEC_NUM + 1)
#define ZXDH_QUE_INTR_VEC_BASE      (ZXDH_MSIX_INTR_DTB_VEC + ZXDH_MSIX_INTR_DTB_VEC_NUM) /* 5 */
#define ZXDH_QUE_INTR_VEC_NUM       256

#define BAR_MSG_ADDR_CHAN_INTERVAL  (2 * 1024) /* channel size */
#define BAR_MSG_PLAYLOAD_OFFSET     (sizeof(struct bar_msg_header))
#define BAR_MSG_PAYLOAD_MAX_LEN     (BAR_MSG_ADDR_CHAN_INTERVAL - sizeof(struct bar_msg_header))

#define MSG_CHAN_RET_ERR_RECV_FAIL              (-11)
#define ZXDH_INDIR_RQT_SIZE 256
#define MODULE_EEPROM_DATA_LEN 128

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
	BAR_EVENT_OVS_WITH_VCB = 36, /* ovs<-->vcb */

	BAR_MSG_MODULE_NUM = 100,
};

static inline const char *module_id_name(int val)
{
	switch (val) {
	case BAR_MODULE_DBG:        return "BAR_MODULE_DBG";
	case BAR_MODULE_TBL:        return "BAR_MODULE_TBL";
	case BAR_MODULE_MISX:       return "BAR_MODULE_MISX";
	case BAR_MODULE_SDA:        return "BAR_MODULE_SDA";
	case BAR_MODULE_RDMA:       return "BAR_MODULE_RDMA";
	case BAR_MODULE_DEMO:       return "BAR_MODULE_DEMO";
	case BAR_MODULE_SMMU:       return "BAR_MODULE_SMMU";
	case BAR_MODULE_MAC:        return "BAR_MODULE_MAC";
	case BAR_MODULE_VDPA:       return "BAR_MODULE_VDPA";
	case BAR_MODULE_VQM:        return "BAR_MODULE_VQM";
	case BAR_MODULE_NP:         return "BAR_MODULE_NP";
	case BAR_MODULE_VPORT:      return "BAR_MODULE_VPORT";
	case BAR_MODULE_BDF:        return "BAR_MODULE_BDF";
	case BAR_MODULE_RISC_READY: return "BAR_MODULE_RISC_READY";
	case BAR_MODULE_REVERSE:    return "BAR_MODULE_REVERSE";
	case BAR_MDOULE_NVME:       return "BAR_MDOULE_NVME";
	case BAR_MDOULE_NPSDK:      return "BAR_MDOULE_NPSDK";
	case BAR_MODULE_NP_TODO:    return "BAR_MODULE_NP_TODO";
	case MODULE_BAR_MSG_TO_PF:  return "MODULE_BAR_MSG_TO_PF";
	case MODULE_BAR_MSG_TO_VF:  return "MODULE_BAR_MSG_TO_VF";
	case MODULE_FLASH:          return "MODULE_FLASH";
	case BAR_MODULE_OFFSET_GET: return "BAR_MODULE_OFFSET_GET";
	case BAR_EVENT_OVS_WITH_VCB: return "BAR_EVENT_OVS_WITH_VCB";
	default: return "NA";
	}
}

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
}; /* 12B */

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
}; /* 32B */

struct zxdh_msg_recviver_mem {
	void    *recv_buffer; /* first 4B is head, followed by payload */
	uint64_t buffer_len;
}; /* 16B */

struct msix_msg {
	uint16_t pcie_id;
	uint16_t vector_risc;
	uint16_t vector_pfvf;
	uint16_t vector_mpf;
};
/* private reps struct */
struct bar_msix_reps {
	uint16_t pcie_id;
	uint16_t check;
	uint16_t vport;
	uint16_t rsv;
} __rte_packed; /* 8B */

struct bar_offset_reps {
	uint16_t check;
	uint16_t rsv;
	uint32_t offset;
	uint32_t length;
} __rte_packed; /* 12B */

struct bar_recv_msg {
	/* fix 4B */
	uint8_t  reps_ok;
	uint16_t reps_len;
	uint8_t  rsv;
	union {
		struct bar_msix_reps   msix_reps;   /* 8B */
		struct bar_offset_reps offset_reps; /* 12B */
	} __rte_packed;
} __rte_packed;

enum pciebar_layout_type {
	URI_VQM      = 0,
	URI_SPINLOCK = 1,
	URI_FWCAP    = 2,
	URI_FWSHR    = 3,
	URI_DRS_SEC  = 4,
	URI_RSV      = 5,
	URI_CTRLCH   = 6,
	URI_1588     = 7,
	URI_QBV      = 8,
	URI_MACPCS   = 9,
	URI_RDMA     = 10,
/* DEBUG PF */
	URI_MNP      = 11,
	URI_MSPM     = 12,
	URI_MVQM     = 13,
	URI_MDPI     = 14,
	URI_NP       = 15,
/* END DEBUG PF */
	URI_MAX,
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

struct tbl_msg_header {
	uint8_t  type;  /* r/w */
	uint8_t  field; /* which table? */
	uint16_t pcieid;
	uint16_t slen;
	uint16_t rsv;
}; /* 8B */
struct tbl_msg_reps_header {
	uint8_t  check;
	uint8_t  rsv;
	uint16_t len;
}; /* 4B */

enum TBL_MSG_TYPE {
	TBL_TYPE_READ,
	TBL_TYPE_WRITE,
	TBL_TYPE_NON,
};

struct bar_offset_params {
	uint64_t virt_addr;  /* Bar space control space virtual address */
	uint16_t pcie_id;
	uint16_t type;  /* Module types corresponding to PCIBAR planning */
};
struct bar_offset_res {
	uint32_t bar_offset;
	uint32_t bar_length;
};

/* vec0  : dev  interrupt
 * vec1~3: risc interrupt
 * vec4  : dtb  interrupt
 */
enum {
	MSIX_FROM_PFVF = ZXDH_MSIX_INTR_MSG_VEC_BASE, /* 1 */
	MSIX_FROM_MPF,   /* 2 */
	MSIX_FROM_RISCV, /* 3 */
	MSG_VEC_NUM      /* 4 */
} MSG_VEC;

enum DRIVER_TYPE {
	MSG_CHAN_END_MPF = 0,
	MSG_CHAN_END_PF,
	MSG_CHAN_END_VF,
	MSG_CHAN_END_RISC,
};

enum MSG_TYPE {
	/* loopback test type */
	TYPE_DEBUG = 0,
	DST_RISCV,
	DST_MPF,
	DST_PF_OR_VF,
	DST_ZF,
	MSG_TYPE_NUM,
};

struct msg_header {
	bool is_async;
	enum MSG_TYPE msg_type;
	enum bar_module_id msg_module_id;
	uint8_t msg_priority;
	uint16_t vport_dst;
	uint16_t qid_dst;
};

struct zxdh_res_para {
	uint64_t virt_addr;
	uint16_t pcie_id;
	uint16_t src_type; /* refer to BAR_DRIVER_TYPE */
};

struct msix_para {
	uint16_t pcie_id;
	uint16_t vector_risc;
	uint16_t vector_pfvf;
	uint16_t vector_mpf;
	uint64_t virt_addr;
	uint16_t driver_type; /* refer to DRIVER_TYPE */
};

struct offset_get_msg {
	uint16_t pcie_id;
	uint16_t type;
}; /* 4B */

typedef int (*zxdh_bar_chan_msg_recv_callback)(void *pay_load, uint16_t len, void *reps_buffer,
					uint16_t *reps_len, void *dev);

/**
 * Init msg_chan_pkt in probe()
 * @return zero for success, negative for failure
 */
int16_t zxdh_msg_chan_pkt_init(void);
void zxdh_msg_chan_pkt_remove(void); /* Remove msg_chan_pkt in probe() */

/**
 * Get the offset value of the specified module
 * @bar_offset_params:  input parameter
 * @bar_offset_res: Module offset and length
 */
int zxdh_get_bar_offset(struct bar_offset_params *paras, struct bar_offset_res *res);

typedef int (*zxdh_bar_chan_msg_recv_callback)(void *pay_load, uint16_t len, void *reps_buffer,
					uint16_t *reps_len, void *dev);

/**
 * Send synchronization messages through PCIE BAR space
 * @in: Message sending information
 * @result: Message result feedback
 * @return: 0 successful, other failures
 */
int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result);

/**
 * PCIE BAR spatial message method, registering message reception callback
 * @module_id: Registration module ID
 * @callback: Pointer to the receive processing function implemented by the module
 * @return: 0 successful, other failures
 * Usually called during driver initialization
 */
int zxdh_bar_chan_msg_recv_register(uint8_t module_id, zxdh_bar_chan_msg_recv_callback callback);

/**
 * PCIE BAR spatial message method, unregistered message receiving callback
 * @module_id: Kernel PCIE device address
 * @return: 0 successful, other failures
 * Called during driver uninstallation
 */
int zxdh_bar_chan_msg_recv_unregister(uint8_t module_id);

/**
 * Provide a message receiving interface for device driver interrupt handling functions
 * @src:  Driver type for sending interrupts
 * @dst:  Device driver's own driver type
 * @virt_addr: The communication bar address of the device
 * @return: 0 successful, other failures
 */
int zxdh_bar_irq_recv(uint8_t src, uint8_t dst, uint64_t virt_addr, void *dev);

/**
 * Initialize spilock and clear the hardware lock address it belongs to
 * @pcie_id: PCIE_id of PF device
 * @bar_base_addr: Bar0 initial base address
 */
int bar_chan_pf_init_spinlock(uint16_t pcie_id, uint64_t bar_base_addr);

int zxdh_bar_chan_enable(struct msix_para *_msix_para, uint16_t *vport);
int zxdh_msg_chan_init(void);
int zxdh_bar_msg_chan_exit(void);

int zxdh_get_res_panel_id(struct zxdh_res_para *in, uint8_t *panel_id);
int zxdh_get_res_hash_id(struct zxdh_res_para *in, uint8_t *hash_id);

int pf_recv_bar_msg(void *pay_load __rte_unused,
					uint16_t len __rte_unused,
					void *reps_buffer __rte_unused,
					uint16_t *reps_len __rte_unused,
					void *eth_dev __rte_unused);
int vf_recv_bar_msg(void *pay_load __rte_unused,
					uint16_t len __rte_unused,
					void *reps_buffer __rte_unused,
					uint16_t *reps_len __rte_unused,
					void *eth_dev __rte_unused);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_MSG_CHAN_H_  */

#ifndef __RNP_MBX_FW_H__
#define __RNP_MBX_FW_H__

struct mbx_fw_cmd_reply;
typedef void (*cookie_cb)(struct mbx_fw_cmd_reply *reply, void *priv);
#define RNP_MAX_SHARE_MEM (8 * 8)
struct mbx_req_cookie {
	int magic;
#define COOKIE_MAGIC 0xCE
	cookie_cb cb;
	int timeout_ms;
	int errcode;

	/* wait_queue_head_t wait; */
	volatile int done;
	int priv_len;
	char priv[RNP_MAX_SHARE_MEM];
};
enum GENERIC_CMD {
	/* link configuration admin commands */
	GET_PHY_ABALITY = 0x0601,
	RESET_PHY = 0x0603,
	SET_EVENT_MASK = 0x0613,
};

enum link_event_mask {
	EVT_LINK_UP = 1,
	EVT_NO_MEDIA = 2,
	EVT_LINK_FAULT = 3,
	EVT_PHY_TEMP_ALARM = 4,
	EVT_EXCESSIVE_ERRORS = 5,
	EVT_SIGNAL_DETECT = 6,
	EVT_AUTO_NEGOTIATION_DONE = 7,
	EVT_MODULE_QUALIFICATION_FAILD = 8,
	EVT_PORT_TX_SUSPEND = 9,
};

enum pma_type {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_1G_BASE_KX,
	PHY_TYPE_SGMII,
	PHY_TYPE_10G_BASE_KR,
	PHY_TYPE_25G_BASE_KR,
	PHY_TYPE_40G_BASE_KR4,
	PHY_TYPE_10G_BASE_SR,
	PHY_TYPE_40G_BASE_SR4,
	PHY_TYPE_40G_BASE_CR4,
	PHY_TYPE_40G_BASE_LR4,
	PHY_TYPE_10G_BASE_LR,
	PHY_TYPE_10G_BASE_ER,
};

struct phy_abilities {
	unsigned char link_stat;
	unsigned char lane_mask;

	int speed;
	short phy_type;
	short nic_mode;
	short pfnum;
	unsigned int fw_version;
	unsigned int axi_mhz;
	uint8_t port_ids[4];
	uint32_t fw_uid;
	uint32_t phy_id;

	int wol_status;

	union {
		unsigned int ext_ablity;
		struct {
			unsigned int valid                 : 1;
			unsigned int wol_en                : 1;
			unsigned int pci_preset_runtime_en : 1;
			unsigned int smbus_en              : 1;
			unsigned int ncsi_en               : 1;
			unsigned int rpu_en                : 1;
			unsigned int v2                    : 1;
			unsigned int pxe_en                : 1;
			unsigned int mctp_en               : 1;
		} e;
	};
} __rte_packed __rte_aligned(4);

/* firmware -> driver */
struct mbx_fw_cmd_reply {
	/* fw must set: DD, CMP, Error(if error), copy value */
	unsigned short flags;
	/* from command: LB,RD,VFC,BUF,SI,EI,FE */
	unsigned short opcode;     /* 2-3: copy from req */
	unsigned short error_code; /* 4-5: 0 if no error */
	unsigned short datalen;    /* 6-7: */
	union {
		struct {
			unsigned int cookie_lo; /* 8-11: */
			unsigned int cookie_hi; /* 12-15: */
		};
		void *cookie;
	};
	/* ===== data ==== [16-64] */
	union {
		struct phy_abilities phy_abilities;
	};
} __rte_packed __rte_aligned(4);

#define MBX_REQ_HDR_LEN            24
/* driver -> firmware */
struct mbx_fw_cmd_req {
	unsigned short flags;     /* 0-1 */
	unsigned short opcode;    /* 2-3 enum LINK_ADM_CMD */
	unsigned short datalen;   /* 4-5 */
	unsigned short ret_value; /* 6-7 */
	union {
		struct {
			unsigned int cookie_lo; /* 8-11 */
			unsigned int cookie_hi; /* 12-15 */
		};
		void *cookie;
	};
	unsigned int reply_lo; /* 16-19 5dw */
	unsigned int reply_hi; /* 20-23 */
	/* === data === [24-64] 7dw */
	union {
		struct {
			int requester;
#define REQUEST_BY_DPDK 0xa1
#define REQUEST_BY_DRV  0xa2
#define REQUEST_BY_PXE  0xa3
		} get_phy_ablity;

		struct {
			unsigned short enable_stat;
			unsigned short event_mask; /* enum link_event_mask */
		} stat_event_mask;
	};
} __rte_packed __rte_aligned(4);

static inline void
build_phy_abalities_req(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags   = 0;
	req->opcode  = GET_PHY_ABALITY;
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

/* enum link_event_mask or */
static inline void
build_link_set_event_mask(struct mbx_fw_cmd_req *req,
			  unsigned short event_mask,
			  unsigned short enable,
			  void *cookie)
{
	req->flags = 0;
	req->opcode = SET_EVENT_MASK;
	req->datalen = sizeof(req->stat_event_mask);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->stat_event_mask.event_mask = event_mask;
	req->stat_event_mask.enable_stat = enable;
}

static inline void
build_reset_phy_req(struct mbx_fw_cmd_req *req,
		    void *cookie)
{
	req->flags = 0;
	req->opcode = RESET_PHY;
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

int rnp_mbx_get_capability(struct rte_eth_dev *dev,
			   int *lane_mask,
			   int *nic_mode);
int rnp_mbx_link_event_enable(struct rte_eth_dev *dev, int enable);
int rnp_mbx_fw_reset_phy(struct rte_eth_dev *dev);
#endif /* __RNP_MBX_FW_H__*/

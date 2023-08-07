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
struct maintain_req {
	int magic;
#define MAINTAIN_MAGIC 0xa6a7a8a9

	int      cmd;
	int      arg0;
	int      req_data_bytes;
	int      reply_bytes;
	char data[0];
} __rte_packed;

enum GENERIC_CMD {
	/* link configuration admin commands */
	GET_PHY_ABALITY = 0x0601,
	GET_MAC_ADDRES = 0x0602,
	RESET_PHY = 0x0603,
	GET_LINK_STATUS = 0x0607,
	LINK_STATUS_EVENT = 0x0608,
	GET_LANE_STATUS = 0x0610,
	SET_EVENT_MASK = 0x0613,
	 /* fw update */
	FW_MAINTAIN = 0x0701,
	SET_DUMP = 0x0a10,
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

struct port_stat {
	u8 phy_addr;		/* Phy MDIO address */

	u8 duplex          : 1; /* FIBRE is always 1,Twisted Pair 1 or 0 */
	u8 autoneg         : 1; /* autoned state */
	u8 fec             : 1;
	u8 an_rev          : 1;
	u8 link_traing     : 1;
	u8 is_sgmii        : 1; /* avild fw >= 0.5.0.17 */
	u16 speed;		/* cur port linked speed */

	u16 pause : 4;
	u16 rev   : 12;
} __rte_packed;

#define RNP_SPEED_CAP_UNKNOWN    (0)
#define RNP_SPEED_CAP_10M_FULL   BIT(2)
#define RNP_SPEED_CAP_100M_FULL  BIT(3)
#define RNP_SPEED_CAP_1GB_FULL   BIT(4)
#define RNP_SPEED_CAP_10GB_FULL  BIT(5)
#define RNP_SPEED_CAP_40GB_FULL  BIT(6)
#define RNP_SPEED_CAP_25GB_FULL  BIT(7)
#define RNP_SPEED_CAP_50GB_FULL  BIT(8)
#define RNP_SPEED_CAP_100GB_FULL BIT(9)
#define RNP_SPEED_CAP_10M_HALF   BIT(10)
#define RNP_SPEED_CAP_100M_HALF  BIT(11)
#define RNP_SPEED_CAP_1GB_HALF   BIT(12)

struct lane_stat_data {
	u8 nr_lane;	     /* 0-3 cur port correspond with hw lane */
	u8 pci_gen	: 4; /* nic cur pci speed genX: 1,2,3 */
	u8 pci_lanes	: 4; /* nic cur pci x1 x2 x4 x8 x16 */
	u8 pma_type;
	u8 phy_type;         /* interface media type */

	u16 linkup	: 1; /* cur port link state */
	u16 duplex	: 1; /* duplex state only RJ45 valid */
	u16 autoneg	: 1; /* autoneg state */
	u16 fec		: 1; /* fec state */
	u16 rev_an	: 1;
	u16 link_traing    : 1; /* link-traing state */
	u16 media_availble : 1;
	u16 is_sgmii       : 1; /* 1: Twisted Pair 0: FIBRE */
	u16 link_fault     : 4;
#define LINK_LINK_FAULT   BIT(0)
#define LINK_TX_FAULT     BIT(1)
#define LINK_RX_FAULT     BIT(2)
#define LINK_REMOTE_FAULT BIT(3)
	u16 is_backplane : 1; /* 1: Backplane Mode */
	union {
		u8 phy_addr; /* Phy MDIO address */
		struct {
			u8 mod_abs : 1;
			u8 fault   : 1;
			u8 tx_dis  : 1;
			u8 los     : 1;
		} sfp;
	};
	u8 sfp_connector;
	u32 speed; /* Current Speed Value */

	u32 si_main;
	u32 si_pre;
	u32 si_post;
	u32 si_tx_boost;
	u32 supported_link; /* Cur nic Support Link cap */
	u32 phy_id;
	u32 advertised_link; /* autoneg mode advertised cap */
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
		char data[0];

		struct mac_addr {
			int lanes;
			struct _addr {
				/* for macaddr:01:02:03:04:05:06
				 *  mac-hi=0x01020304 mac-lo=0x05060000
				 */
				unsigned char mac[8];
			} addrs[4];
		} mac_addr;

		struct lane_stat_data lanestat;
		struct phy_abilities phy_abilities;
	};
} __rte_packed __rte_aligned(4);
/* == flags == */
#define FLAGS_DD	BIT(0) /* driver clear 0, FW must set 1 */
#define FLAGS_CMP	BIT(1) /* driver clear 0, FW mucst set */
/* driver clear 0, FW must set only if it reporting an error */
#define FLAGS_ERR	BIT(2)

#define MBX_REQ_HDR_LEN		(24)
#define RNP_ALARM_INTERVAL	(50000) /* unit us */
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
			int lane_mask;
			int pfvf_num;
		} get_mac_addr;

		struct {
			unsigned short enable_stat;
			unsigned short event_mask; /* enum link_event_mask */
		} stat_event_mask;

		struct {
			int nr_lane;
		} get_lane_st;

		struct {
			int cmd;
#define MT_WRITE_FLASH 1
			int arg0;
			int req_bytes;
			int reply_bytes;
			int ddr_lo;
			int ddr_hi;
		} maintain;

		struct {
			int flag;
			int nr_lane;
		} set_dump;

		struct {
			unsigned short changed_lanes;
			unsigned short lane_status;
			unsigned int port_st_magic;
#define SPEED_VALID_MAGIC 0xa4a6a8a9
			struct port_stat st[4];
		} link_stat; /* FW->RC */
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

static inline void
build_get_macaddress_req(struct mbx_fw_cmd_req *req,
			 int lane_mask,
			 int pfvfnum,
			 void *cookie)
{
	req->flags = 0;
	req->opcode = GET_MAC_ADDRES;
	req->datalen = sizeof(req->get_mac_addr);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->get_mac_addr.lane_mask = lane_mask;
	req->get_mac_addr.pfvf_num = pfvfnum;
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

static inline void
build_get_lane_status_req(struct mbx_fw_cmd_req *req,
			  int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_LANE_STATUS;
	req->datalen = sizeof(req->get_lane_st);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_lane_st.nr_lane = nr_lane;
}

static inline void
build_maintain_req(struct mbx_fw_cmd_req *req,
		   void *cookie,
		   int cmd,
		   int arg0,
		   int req_bytes,
		   int reply_bytes,
		   u32 dma_phy_lo,
		   u32 dma_phy_hi)
{
	req->flags = 0;
	req->opcode = FW_MAINTAIN;
	req->datalen = sizeof(req->maintain);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->maintain.cmd = cmd;
	req->maintain.arg0 = arg0;
	req->maintain.req_bytes = req_bytes;
	req->maintain.reply_bytes = reply_bytes;
	req->maintain.ddr_lo = dma_phy_lo;
	req->maintain.ddr_hi = dma_phy_hi;
}

static inline void
build_set_dump(struct mbx_fw_cmd_req *req, int nr_lane, int flag)
{
	req->flags = 0;
	req->opcode = SET_DUMP;
	req->datalen = sizeof(req->set_dump);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->set_dump.flag = flag;
	req->set_dump.nr_lane = nr_lane;
}

int rnp_mbx_get_capability(struct rte_eth_dev *dev,
			   int *lane_mask,
			   int *nic_mode);
int rnp_mbx_link_event_enable(struct rte_eth_dev *dev, int enable);
int rnp_mbx_fw_reset_phy(struct rte_eth_dev *dev);
int
rnp_fw_get_macaddr(struct rte_eth_dev *dev,
		   int pfvfnum,
		   u8 *mac_addr,
		   int nr_lane);
int rnp_mbx_get_lane_stat(struct rte_eth_dev *dev);
int rnp_fw_update(struct rnp_eth_adapter *adapter);
int rnp_hw_set_fw_10g_1g_auto_detch(struct rte_eth_dev *dev, int enable);
int rnp_hw_set_fw_force_speed_1g(struct rte_eth_dev *dev, int enable);
void rnp_link_stat_mark(struct rnp_hw *hw, int nr_lane, int up);
void rnp_link_report(struct rte_eth_dev *dev, bool link_en);
int rnp_fw_msg_handler(struct rnp_eth_adapter *adapter);
#endif /* __RNP_MBX_FW_H__*/

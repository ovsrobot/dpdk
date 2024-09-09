/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#include <stdint.h>

#define DPP_PORT_NAME_MAX                   (32)
#define DPP_SMMU1_READ_REG_MAX_NUM          (16)
#define DPP_DIR_TBL_BUF_MAX_NUM             (DPP_SMMU1_READ_REG_MAX_NUM)
#define DPP_ETCAM_BLOCK_NUM                 (8)
#define DPP_SMMU0_LPM_AS_TBL_ID_NUM         (8)
#define SE_NIC_RES_TYPE                      0

#define ZXDH_SDT_VPORT_ATT_TABLE            ((uint32_t)(1))
#define ZXDH_SDT_PANEL_ATT_TABLE            ((uint32_t)(2))
#define ZXDH_SDT_RSS_ATT_TABLE              ((uint32_t)(3))
#define ZXDH_SDT_VLAN_ATT_TABLE             ((uint32_t)(4))
#define ZXDH_SDT_BROCAST_ATT_TABLE          ((uint32_t)(6))
#define ZXDH_SDT_UNICAST_ATT_TABLE          ((uint32_t)(10))
#define ZXDH_SDT_MULTICAST_ATT_TABLE        ((uint32_t)(11))

#define ZXDH_SDT_L2_ENTRY_TABLE0            ((uint32_t)(64))
#define ZXDH_SDT_L2_ENTRY_TABLE1            ((uint32_t)(65))
#define ZXDH_SDT_L2_ENTRY_TABLE2            ((uint32_t)(66))
#define ZXDH_SDT_L2_ENTRY_TABLE3            ((uint32_t)(67))
#define ZXDH_SDT_L2_ENTRY_TABLE4            ((uint32_t)(68))
#define ZXDH_SDT_L2_ENTRY_TABLE5            ((uint32_t)(69))

#define ZXDH_SDT_MC_TABLE0                  ((uint32_t)(76))
#define ZXDH_SDT_MC_TABLE1                  ((uint32_t)(77))
#define ZXDH_SDT_MC_TABLE2                  ((uint32_t)(78))
#define ZXDH_SDT_MC_TABLE3                  ((uint32_t)(79))
#define ZXDH_SDT_MC_TABLE4                  ((uint32_t)(80))
#define ZXDH_SDT_MC_TABLE5                  ((uint32_t)(81))

#define MK_SDT_NO(table, hash_idx) \
	(ZXDH_SDT_##table##_TABLE0 + hash_idx)

typedef struct dpp_dtb_addr_info_t {
	uint32_t sdt_no;
	uint32_t size;
	uint32_t phy_addr;
	uint32_t vir_addr;
} DPP_DTB_ADDR_INFO_T;

typedef struct dpp_dev_init_ctrl_t {
	uint32_t vport;
	char  port_name[DPP_PORT_NAME_MAX];
	uint32_t vector;
	uint32_t queue_id;
	uint32_t np_bar_offset;
	uint32_t np_bar_len;
	uint32_t pcie_vir_addr;
	uint32_t down_phy_addr;
	uint32_t down_vir_addr;
	uint32_t dump_phy_addr;
	uint32_t dump_vir_addr;
	uint32_t dump_sdt_num;
	DPP_DTB_ADDR_INFO_T dump_addr_info[];
} DPP_DEV_INIT_CTRL_T;

typedef struct dpp_apt_hash_func_res_t {
	uint32_t func_id;
	uint32_t zblk_num;
	uint32_t zblk_bitmap;
	uint32_t ddr_dis;
} DPP_APT_HASH_FUNC_RES_T;

typedef enum dpp_hash_ddr_width_mode {
	DDR_WIDTH_INVALID = 0,
	DDR_WIDTH_256b,
	DDR_WIDTH_512b,
} DPP_HASH_DDR_WIDTH_MODE;

typedef struct dpp_apt_hash_bulk_res_t {
	uint32_t func_id;
	uint32_t bulk_id;
	uint32_t zcell_num;
	uint32_t zreg_num;
	uint32_t ddr_baddr;
	uint32_t ddr_item_num;
	DPP_HASH_DDR_WIDTH_MODE ddr_width_mode;
	uint32_t ddr_crc_sel;
	uint32_t ddr_ecc_en;
} DPP_APT_HASH_BULK_RES_T;


typedef struct dpp_sdt_tbl_hash_t {
	uint32_t table_type;
	uint32_t hash_id;
	uint32_t hash_table_width;
	uint32_t key_size;
	uint32_t hash_table_id;
	uint32_t learn_en;
	uint32_t keep_alive;
	uint32_t keep_alive_baddr;
	uint32_t rsp_mode;
	uint32_t hash_clutch_en;
} DPP_SDTTBL_HASH_T;

typedef struct dpp_hash_entry {
	uint8_t *p_key;
	uint8_t *p_rst;
} DPP_HASH_ENTRY;


typedef uint32_t (*DPP_APT_HASH_ENTRY_SET_FUNC)(void *Data, DPP_HASH_ENTRY *Entry);
typedef uint32_t (*DPP_APT_HASH_ENTRY_GET_FUNC)(void *Data, DPP_HASH_ENTRY *Entry);

typedef struct dpp_apt_hash_table_t {
	uint32_t sdtNo;
	uint32_t sdt_partner;
	DPP_SDTTBL_HASH_T hashSdt;
	uint32_t tbl_flag;
	DPP_APT_HASH_ENTRY_SET_FUNC hash_set_func;
	DPP_APT_HASH_ENTRY_GET_FUNC hash_get_func;
} DPP_APT_HASH_TABLE_T;

typedef struct dpp_apt_hash_res_init_t {
	uint32_t func_num;
	uint32_t bulk_num;
	uint32_t tbl_num;
	DPP_APT_HASH_FUNC_RES_T *func_res;
	DPP_APT_HASH_BULK_RES_T *bulk_res;
	DPP_APT_HASH_TABLE_T  *tbl_res;
} DPP_APT_HASH_RES_INIT_T;

typedef struct dpp_sdt_tbl_eram_t {
	uint32_t table_type;
	uint32_t eram_mode;
	uint32_t eram_base_addr;
	uint32_t eram_table_depth;
	uint32_t eram_clutch_en;
} DPP_SDTTBL_ERAM_T;

typedef uint32_t (*DPP_APT_ERAM_SET_FUNC)(void *Data, uint32_t buf[4]);
typedef uint32_t (*DPP_APT_ERAM_GET_FUNC)(void *Data, uint32_t buf[4]);

typedef struct dpp_apt_eram_table_t {
	uint32_t sdtNo;
	DPP_SDTTBL_ERAM_T ERamSdt;
	uint32_t opr_mode;
	uint32_t rd_mode;
	DPP_APT_ERAM_SET_FUNC  eram_set_func;
	DPP_APT_ERAM_GET_FUNC  eram_get_func;
} DPP_APT_ERAM_TABLE_T;


typedef struct dpp_apt_eram_res_init_t {
	uint32_t tbl_num;
	DPP_APT_ERAM_TABLE_T *eram_res;
} DPP_APT_ERAM_RES_INIT_T;

typedef struct dpp_apt_stat_res_init_t {
	uint32_t eram_baddr;
	uint32_t eram_depth;
	uint32_t ddr_baddr;
	uint32_t ppu_ddr_offset;
} DPP_APT_STAT_RES_INIT_T;

typedef enum stat_cnt_mode_e {
	STAT_64_MODE  = 0,
	STAT_128_MODE = 1,
	STAT_MAX_MODE,
} STAT_CNT_MODE_E;

typedef struct dpp_dtb_user_entry_t {
	uint32_t sdt_no;
	void *p_entry_data;
} DPP_DTB_USER_ENTRY_T;


int dpp_dtb_hash_offline_delete(uint32_t dev_id, uint32_t queue_id,
						uint32_t sdt_no, uint32_t flush_mode);
int dpp_dtb_hash_online_delete(uint32_t dev_id, uint32_t queue_id, uint32_t sdt_no);
int dpp_apt_hash_res_get(uint32_t type, DPP_APT_HASH_RES_INIT_T *HashResInit);
int dpp_apt_eram_res_get(uint32_t type, DPP_APT_ERAM_RES_INIT_T *EramResInit);

int dpp_apt_stat_res_get(uint32_t type, DPP_APT_STAT_RES_INIT_T *StatResInit);
int dpp_apt_hash_global_res_init(uint32_t dev_id);
int dpp_apt_hash_func_res_init(uint32_t dev_id, uint32_t func_num,
							   DPP_APT_HASH_FUNC_RES_T *HashFuncRes);
int dpp_apt_hash_bulk_res_init(uint32_t dev_id, uint32_t bulk_num,
							   DPP_APT_HASH_BULK_RES_T *BulkRes);
int dpp_apt_hash_tbl_res_init(uint32_t dev_id, uint32_t tbl_num,
							   DPP_APT_HASH_TABLE_T *HashTbl);
int dpp_apt_eram_res_init(uint32_t dev_id, uint32_t tbl_num,
						  DPP_APT_ERAM_TABLE_T *EramTbl);
int dpp_stat_ppu_eram_baddr_set(uint32_t dev_id, uint32_t ppu_eram_baddr);
int dpp_stat_ppu_eram_depth_set(uint32_t dev_id, uint32_t ppu_eram_depth);
int dpp_se_cmmu_smmu1_cfg_set(uint32_t dev_id, uint32_t base_addr);
int dpp_stat_ppu_ddr_baddr_set(uint32_t dev_id, uint32_t ppu_ddr_baddr);

int dpp_host_np_init(uint32_t dev_id, DPP_DEV_INIT_CTRL_T *p_dev_init_ctrl);
int dpp_np_online_uninstall(uint32_t dev_id,
							char *port_name,
							uint32_t queue_id);

int dpp_dtb_stat_ppu_cnt_get(uint32_t dev_id,
							uint32_t queue_id,
							STAT_CNT_MODE_E rd_mode,
							uint32_t index,
							uint32_t *p_data);

int dpp_dtb_entry_get(uint32_t dev_id,
					uint32_t queue_id,
					DPP_DTB_USER_ENTRY_T *GetEntry,
					uint32_t srh_mode);
int dpp_dtb_table_entry_write(uint32_t dev_id,
							uint32_t queue_id,
							uint32_t entryNum,
							DPP_DTB_USER_ENTRY_T *DownEntrys);
int dpp_dtb_table_entry_delete(uint32_t dev_id,
							uint32_t queue_id,
							uint32_t entryNum,
							DPP_DTB_USER_ENTRY_T *DeleteEntrys);

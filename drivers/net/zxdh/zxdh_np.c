/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "zxdh_np.h"
#include "zxdh_logs.h"
#include "zxdh_msg.h"

static ZXDH_DEV_MGR_T g_dev_mgr;
static ZXDH_SDT_MGR_T g_sdt_mgr;
static uint32_t g_table_type[ZXDH_DEV_CHANNEL_MAX][ZXDH_DEV_SDT_ID_MAX];
static ZXDH_PPU_CLS_BITMAP_T g_ppu_cls_bit_map[ZXDH_DEV_CHANNEL_MAX];
static ZXDH_DTB_MGR_T *p_dpp_dtb_mgr[ZXDH_DEV_CHANNEL_MAX];
static ZXDH_SDT_TBL_DATA_T g_sdt_info[ZXDH_DEV_CHANNEL_MAX][ZXDH_DEV_SDT_ID_MAX];
static ZXDH_PPU_STAT_CFG_T g_ppu_stat_cfg[ZXDH_DEV_CHANNEL_MAX];
static uint64_t g_np_fw_compat_addr[ZXDH_DEV_CHANNEL_MAX];
static const ZXDH_VERSION_COMPATIBLE_REG_T g_np_sdk_version = {
	ZXDH_NPSDK_COMPAT_ITEM_ID, 1, 0, 0, 0, {0} };
static const uint32_t hardware_ep_id[5] = {5, 6, 7, 8, 9};

static ZXDH_FIELD_T g_smmu0_smmu0_cpu_ind_cmd_reg[] = {
	{"cpu_ind_rw", ZXDH_FIELD_FLAG_RW, 31, 1, 0x0, 0x0},
	{"cpu_ind_rd_mode", ZXDH_FIELD_FLAG_RW, 30, 1, 0x0, 0x0},
	{"cpu_req_mode", ZXDH_FIELD_FLAG_RW, 27, 2, 0x0, 0x0},
	{"cpu_ind_addr", ZXDH_FIELD_FLAG_RW, 25, 26, 0x0, 0x0},
};

static ZXDH_FIELD_T g_smmu0_smmu0_cpu_ind_rd_done_reg[] = {
	{"cpu_ind_rd_done", ZXDH_FIELD_FLAG_RO, 0, 1, 0x0, 0x0},
};

static ZXDH_FIELD_T g_smmu0_smmu0_cpu_ind_rdat0_reg[] = {
	{"cpu_ind_rdat0", ZXDH_FIELD_FLAG_RO, 31, 32, 0x0, 0x0},
};

static ZXDH_FIELD_T g_smmu0_smmu0_cpu_ind_rdat1_reg[] = {
	{"cpu_ind_rdat1", ZXDH_FIELD_FLAG_RO, 31, 32, 0x0, 0x0},
};

static ZXDH_FIELD_T g_smmu0_smmu0_cpu_ind_rdat2_reg[] = {
	{"cpu_ind_rdat2", ZXDH_FIELD_FLAG_RO, 31, 32, 0x0, 0x0},
};

static ZXDH_FIELD_T g_smmu0_smmu0_cpu_ind_rdat3_reg[] = {
	{"cpu_ind_rdat3", ZXDH_FIELD_FLAG_RO, 31, 32, 0x0, 0x0},
};

static ZXDH_FIELD_T g_smmu0_smmu0_wr_arb_cpu_rdy_reg[] = {
	{"wr_arb_cpu_rdy", ZXDH_FIELD_FLAG_RO, 0, 1, 0x1, 0x0},
};

static ZXDH_FIELD_T g_dtb4k_dtb_enq_info_queue_buf_space_left_0_127_reg[] = {
	{"info_queue_buf_space_left", ZXDH_FIELD_FLAG_RO, 5, 6, 0x20, 0x0},
};

static ZXDH_FIELD_T g_dtb4k_dtb_enq_cfg_epid_v_func_num_0_127_reg[] = {
	{"dbi_en", ZXDH_FIELD_FLAG_RW, 31, 1, 0x0, 0x0},
	{"queue_en", ZXDH_FIELD_FLAG_RW, 30, 1, 0x0, 0x0},
	{"cfg_epid", ZXDH_FIELD_FLAG_RW, 27, 4, 0x0, 0x0},
	{"cfg_vfunc_num", ZXDH_FIELD_FLAG_RW, 23, 8, 0x0, 0x0},
	{"cfg_vector", ZXDH_FIELD_FLAG_RW, 14, 7, 0x0, 0x0},
	{"cfg_func_num", ZXDH_FIELD_FLAG_RW, 7, 3, 0x0, 0x0},
	{"cfg_vfunc_active", ZXDH_FIELD_FLAG_RW, 0, 1, 0x0, 0x0},
};

static ZXDH_DTB_FIELD_T g_dtb_ddr_table_cmd_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"rw_len", 123, 2},
	{"v46_flag", 121, 1},
	{"lpm_wr_vld", 120, 1},
	{"baddr", 119, 20},
	{"ecc_en", 99, 1},
	{"rw_addr", 29, 30},
};

static ZXDH_DTB_FIELD_T g_dtb_eram_table_cmd_1_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"data_mode", 123, 2},
	{"cpu_wr", 121, 1},
	{"cpu_rd", 120, 1},
	{"cpu_rd_mode", 119, 1},
	{"addr", 113, 26},
	{"data_h", 0, 1},
};

static ZXDH_DTB_FIELD_T g_dtb_eram_table_cmd_64_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"data_mode", 123, 2},
	{"cpu_wr", 121, 1},
	{"cpu_rd", 120, 1},
	{"cpu_rd_mode", 119, 1},
	{"addr", 113, 26},
	{"data_h", 63, 32},
	{"data_l", 31, 32},
};

static ZXDH_DTB_FIELD_T g_dtb_eram_table_cmd_128_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"data_mode", 123, 2},
	{"cpu_wr", 121, 1},
	{"cpu_rd", 120, 1},
	{"cpu_rd_mode", 119, 1},
	{"addr", 113, 26},
};

static ZXDH_DTB_FIELD_T g_dtb_zcam_table_cmd_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"ram_reg_flag", 123, 1},
	{"zgroup_id", 122, 2},
	{"zblock_id", 120, 3},
	{"zcell_id", 117, 2},
	{"mask", 115, 4},
	{"sram_addr", 111, 9},
};

static ZXDH_DTB_FIELD_T g_dtb_etcam_table_cmd_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"block_sel", 123, 3},
	{"init_en", 120, 1},
	{"row_or_col_msk", 119, 1},
	{"vben", 118, 1},
	{"reg_tcam_flag", 117, 1},
	{"uload", 116, 8},
	{"rd_wr", 108, 1},
	{"wr_mode", 107, 8},
	{"data_or_mask", 99, 1},
	{"addr", 98, 9},
	{"vbit", 89, 8},
};

static ZXDH_DTB_FIELD_T g_dtb_mc_hash_table_cmd_info[] = {
	{"valid", 127, 1},
	{"type_mode", 126, 3},
	{"std_h", 63, 32},
	{"std_l", 31, 32},
};

static ZXDH_DTB_TABLE_T g_dpp_dtb_table_info[] = {
	{
		"ddr",
		ZXDH_DTB_TABLE_DDR,
		8,
		g_dtb_ddr_table_cmd_info,
	},
	{
		"eram 1 bit",
		ZXDH_DTB_TABLE_ERAM_1,
		8,
		g_dtb_eram_table_cmd_1_info,
	},
	{
		"eram 64 bit",
		ZXDH_DTB_TABLE_ERAM_64,
		9,
		g_dtb_eram_table_cmd_64_info,
	},
	{
		"eram 128 bit",
		ZXDH_DTB_TABLE_ERAM_128,
		7,
		g_dtb_eram_table_cmd_128_info,
	},
	{
		"zcam",
		ZXDH_DTB_TABLE_ZCAM,
		8,
		g_dtb_zcam_table_cmd_info,
	},
	{
		"etcam",
		ZXDH_DTB_TABLE_ETCAM,
		13,
		g_dtb_etcam_table_cmd_info,
	},
	{
		"mc_hash",
		ZXDH_DTB_TABLE_MC_HASH,
		4,
		g_dtb_mc_hash_table_cmd_info
	},
};

#define ZXDH_SDT_MGR_PTR_GET()    (&g_sdt_mgr)
#define ZXDH_SDT_SOFT_TBL_GET(id) (g_sdt_mgr.sdt_tbl_array[id])
#define ZXDH_DEV_INFO_GET(id) (g_dev_mgr.p_dev_array[id])

#define ZXDH_DTB_LEN(cmd_type, int_en, data_len) \
	(((data_len) & 0x3ff) | \
	((int_en) << 29) | \
	((cmd_type) << 30))

#define ZXDH_COMM_MASK_BIT(_bitnum_)\
	(0x1U << (_bitnum_))

#define ZXDH_COMM_GET_BIT_MASK(_inttype_, _bitqnt_)\
	((_inttype_)(((_bitqnt_) < 32)))

#define ZXDH_COMM_UINT32_GET_BITS(_uidst_, _uisrc_, _uistartpos_, _uilen_)\
	((_uidst_) = (((_uisrc_) >> (_uistartpos_)) & \
	(ZXDH_COMM_GET_BIT_MASK(uint32_t, (_uilen_)))))

#define ZXDH_REG_DATA_MAX      (128)

#define ZXDH_COMM_CHECK_DEV_POINT(dev_id, point)\
do {\
	if (NULL == (point)) {\
		PMD_DRV_LOG(ERR, "dev: %d [POINT NULL]", (dev_id));\
		RTE_ASSERT(0);\
	} \
} while (0)

#define ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, becall)\
do {\
	if ((rc) != 0) {\
		PMD_DRV_LOG(ERR, "dev: %d, %s failed!", (dev_id), becall);\
		RTE_ASSERT(0);\
	} \
} while (0)

#define ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, becall)\
do {\
	if ((rc) != 0) {\
		PMD_DRV_LOG(ERR, "%s failed!", becall);\
	} \
} while (0)

#define ZXDH_COMM_CHECK_RC(rc, becall)\
do {\
	if ((rc) != 0) {\
		PMD_DRV_LOG(ERR, "%s failed!", becall);\
		RTE_ASSERT(0);\
	} \
} while (0)

#define ZXDH_COMM_CHECK_POINT(point)\
do {\
	if ((point) == NULL) {\
		PMD_DRV_LOG(ERR, "[POINT NULL]");\
		RTE_ASSERT(0);\
	} \
} while (0)

static inline uint16_t zxdh_np_comm_convert16(uint16_t w_data)
{
	return ((w_data) & 0xff) << 8 | ((w_data) & 0xff00) >> 8;
}

static inline uint32_t
zxdh_np_comm_convert32(uint32_t dw_data)
{
	return ((dw_data) & 0xff) << 24 | ((dw_data) & 0xff00) << 8 |
		((dw_data) & 0xff0000) >> 8 | ((dw_data) & 0xff000000) >> 24;
}

#define ZXDH_COMM_CONVERT16(w_data) \
			zxdh_np_comm_convert16(w_data)

#define ZXDH_COMM_CONVERT32(w_data) \
			zxdh_np_comm_convert32(w_data)

#define ZXDH_DTB_TAB_UP_WR_INDEX_GET(DEV_ID, QUEUE_ID)       \
		(p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_up.wr_index)

#define ZXDH_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(DEV_ID, QUEUE_ID, INDEX)     \
	(p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_up.user_addr[(INDEX)].user_flag)

#define ZXDH_DTB_TAB_UP_USER_PHY_ADDR_GET(DEV_ID, QUEUE_ID, INDEX)     \
		(p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_up.user_addr[(INDEX)].phy_addr)

#define ZXDH_DTB_TAB_UP_DATA_LEN_GET(DEV_ID, QUEUE_ID, INDEX)       \
		(p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_up.data_len[(INDEX)])

#define ZXDH_DTB_TAB_UP_VIR_ADDR_GET(DEV_ID, QUEUE_ID, INDEX)     \
		((INDEX) * p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_up.item_size)

#define ZXDH_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_ID, QUEUE_ID, INDEX)   \
		((INDEX) * p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_down.item_size)

#define ZXDH_DTB_TAB_DOWN_WR_INDEX_GET(DEV_ID, QUEUE_ID)       \
		(p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].tab_down.wr_index)

#define ZXDH_DTB_QUEUE_INIT_FLAG_GET(DEV_ID, QUEUE_ID)       \
		(p_dpp_dtb_mgr[(DEV_ID)]->queue_info[(QUEUE_ID)].init_flag)

static inline void
zxdh_np_comm_spinlock_create(ZXDH_SPINLOCK_T *p_spinlock)
{
	rte_spinlock_init(&p_spinlock->spinlock);
}

static inline void
zxdh_np_comm_spinlock_lock(ZXDH_SPINLOCK_T *p_spinlock)
{
	rte_spinlock_lock(&p_spinlock->spinlock);
}

static inline void
zxdh_np_comm_spinlock_unlock(ZXDH_SPINLOCK_T *p_spinlock)
{
	rte_spinlock_unlock(&p_spinlock->spinlock);
}

static uint32_t
zxdh_np_comm_is_big_endian(void)
{
	ZXDH_ENDIAN_U c_data;

	c_data.a = 1;

	if (c_data.b == 1)
		return 0;
	else
		return 1;
}

static void
zxdh_np_comm_swap(uint8_t *p_uc_data, uint32_t dw_byte_len)
{
	uint16_t *p_w_tmp = NULL;
	uint32_t *p_dw_tmp = NULL;
	uint32_t dw_byte_num;
	uint8_t uc_byte_mode;
	uint32_t uc_is_big_flag;
	uint32_t i;

	p_dw_tmp = (uint32_t *)(p_uc_data);
	uc_is_big_flag = zxdh_np_comm_is_big_endian();
	if (uc_is_big_flag)
		return;

	dw_byte_num  = dw_byte_len >> 2;
	uc_byte_mode = dw_byte_len % 4 & 0xff;

	for (i = 0; i < dw_byte_num; i++) {
		(*p_dw_tmp) = ZXDH_COMM_CONVERT32(*p_dw_tmp);
		p_dw_tmp++;
	}

	if (uc_byte_mode > 1) {
		p_w_tmp = (uint16_t *)(p_dw_tmp);
		(*p_w_tmp) = ZXDH_COMM_CONVERT16(*p_w_tmp);
	}
}

static uint32_t
zxdh_np_dev_init(void)
{
	if (g_dev_mgr.is_init) {
		PMD_DRV_LOG(ERR, "Dev is already initialized");
		return 0;
	}

	g_dev_mgr.device_num = 0;
	g_dev_mgr.is_init    = 1;

	return 0;
}

static void
zxdh_np_dev_vport_get(uint32_t dev_id, uint32_t *vport)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = &g_dev_mgr;
	ZXDH_DEV_CFG_T *p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	*vport = p_dev_info->vport;
}

static void
zxdh_np_dev_agent_addr_get(uint32_t dev_id, uint64_t *agent_addr)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = &g_dev_mgr;
	ZXDH_DEV_CFG_T *p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	*agent_addr = p_dev_info->agent_addr;
}

static void
zxdh_np_dev_fw_bar_msg_num_set(uint32_t dev_id, uint32_t bar_msg_num)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = &g_dev_mgr;
	ZXDH_DEV_CFG_T *p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	p_dev_info->fw_bar_msg_num = bar_msg_num;

	PMD_DRV_LOG(INFO, "fw_bar_msg_num_set:fw support agent msg num = %u!", bar_msg_num);
}

static void
zxdh_np_dev_fw_bar_msg_num_get(uint32_t dev_id, uint32_t *bar_msg_num)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = &g_dev_mgr;
	ZXDH_DEV_CFG_T *p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	*bar_msg_num = p_dev_info->fw_bar_msg_num;
}

static uint32_t
zxdh_np_dev_opr_spinlock_get(uint32_t dev_id, uint32_t type, ZXDH_SPINLOCK_T **p_spinlock_out)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = &g_dev_mgr;
	ZXDH_DEV_CFG_T *p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	if (p_dev_info == NULL) {
		PMD_DRV_LOG(ERR, "Get dev_info[ %d ] fail!", dev_id);
		return ZXDH_DEV_TYPE_INVALID;
	}

	switch (type) {
	case ZXDH_DEV_SPINLOCK_T_DTB:
		*p_spinlock_out = &p_dev_info->dtb_spinlock;
		break;
	case ZXDH_DEV_SPINLOCK_T_SMMU0:
		*p_spinlock_out = &p_dev_info->smmu0_spinlock;
		break;
	default:
		PMD_DRV_LOG(ERR, "spinlock type is invalid!");
		return ZXDH_ERR;
	}

	return ZXDH_OK;
}

static uint32_t
zxdh_np_dev_dtb_opr_spinlock_get(uint32_t dev_id, uint32_t type,
			uint32_t index, ZXDH_SPINLOCK_T **p_spinlock_out)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = &g_dev_mgr;
	ZXDH_DEV_CFG_T *p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	switch (type) {
	case ZXDH_DEV_SPINLOCK_T_DTB:
		*p_spinlock_out = &p_dev_info->dtb_queue_spinlock[index];
		break;
	default:
		PMD_DRV_LOG(ERR, "spinlock type is invalid!");
		return ZXDH_ERR;
	}

	return ZXDH_OK;
}

static uint32_t
zxdh_np_dev_read_channel(uint32_t dev_id, uint32_t addr, uint32_t size, uint32_t *p_data)
{
	ZXDH_DEV_CFG_T *p_dev_info = NULL;

	p_dev_info = ZXDH_DEV_INFO_GET(dev_id);

	if (p_dev_info == NULL) {
		PMD_DRV_LOG(ERR, "Error: Channel[%d] dev is not exist",
			dev_id);
		return ZXDH_ERR;
	}
	if (p_dev_info->access_type == ZXDH_DEV_ACCESS_TYPE_PCIE) {
		p_dev_info->p_pcie_read_fun(dev_id, addr, size, p_data);
	} else {
		PMD_DRV_LOG(ERR, "Dev access type[ %d ] is invalid",
			p_dev_info->access_type);
		return ZXDH_ERR;
	}

	return ZXDH_OK;
}

static uint32_t
zxdh_np_dev_write_channel(uint32_t dev_id, uint32_t addr, uint32_t size, uint32_t *p_data)
{
	ZXDH_DEV_CFG_T *p_dev_info = NULL;

	p_dev_info = ZXDH_DEV_INFO_GET(dev_id);

	if (p_dev_info == NULL) {
		PMD_DRV_LOG(ERR, "Error: Channel[%d] dev is not exist",
			dev_id);
		return ZXDH_ERR;
	}
	if (p_dev_info->access_type == ZXDH_DEV_ACCESS_TYPE_PCIE) {
		p_dev_info->p_pcie_write_fun(dev_id, addr, size, p_data);
	} else {
		PMD_DRV_LOG(ERR, "Dev access type[ %d ] is invalid",
			p_dev_info->access_type);
		return ZXDH_ERR;
	}

	return ZXDH_OK;
}

static void
zxdh_np_pci_write32(uint64_t abs_addr, uint32_t *p_data)
{
	uint32_t data = 0;
	uint64_t addr = 0;

	data = *p_data;

	if (zxdh_np_comm_is_big_endian())
		data = ZXDH_COMM_CONVERT32(data);

	addr = abs_addr + ZXDH_SYS_VF_NP_BASE_OFFSET;
	*((volatile uint32_t *)addr) = data;
}

static void
zxdh_np_pci_read32(uint64_t abs_addr, uint32_t *p_data)
{
	uint32_t data = 0;
	uint64_t addr = 0;

	addr = abs_addr + ZXDH_SYS_VF_NP_BASE_OFFSET;
	data = *((volatile uint32_t *)addr);

	if (zxdh_np_comm_is_big_endian())
		data = ZXDH_COMM_CONVERT32(data);

	*p_data = data;
}

static uint64_t
zxdh_np_dev_get_pcie_addr(uint32_t dev_id)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = NULL;
	ZXDH_DEV_CFG_T *p_dev_info = NULL;

	p_dev_mgr = &g_dev_mgr;
	p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	if (p_dev_info == NULL)
		return ZXDH_DEV_TYPE_INVALID;

	return p_dev_info->pcie_addr;
}

static void
zxdh_np_dev_pcie_default_write(uint32_t dev_id, uint32_t addr, uint32_t size, uint32_t *p_data)
{
	uint32_t i;
	uint64_t abs_addr = 0;

	abs_addr = zxdh_np_dev_get_pcie_addr(dev_id) + addr;

	for (i = 0; i < size; i++)
		zxdh_np_pci_write32(abs_addr + 4 * i, p_data + i);
}

static void
zxdh_np_dev_pcie_default_read(uint32_t dev_id, uint32_t addr, uint32_t size, uint32_t *p_data)
{
	uint32_t i;
	uint64_t abs_addr = 0;

	abs_addr = zxdh_np_dev_get_pcie_addr(dev_id) + addr;

	for (i = 0; i < size; i++)
		zxdh_np_pci_read32(abs_addr + 4 * i, p_data + i);
}

static uint32_t
zxdh_np_read(uint32_t dev_id, uint32_t addr, uint32_t *p_data)
{
	return zxdh_np_dev_read_channel(dev_id, addr, 1, p_data);
}

static uint32_t
zxdh_np_write(uint32_t dev_id, uint32_t addr, uint32_t *p_data)
{
	return zxdh_np_dev_write_channel(dev_id, addr, 1, p_data);
}

static uint32_t
zxdh_np_se_smmu0_write(uint32_t dev_id, uint32_t addr, uint32_t *p_data)
{
	return zxdh_np_write(dev_id, addr, p_data);
}

static uint32_t
zxdh_np_se_smmu0_read(uint32_t dev_id, uint32_t addr, uint32_t *p_data)
{
	return zxdh_np_read(dev_id, addr, p_data);
}

static ZXDH_REG_T g_dpp_reg_info[] = {
	{
		.reg_name = "cpu_ind_cmd",
		.reg_no = 669,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x14,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 4,
		.p_fields = g_smmu0_smmu0_cpu_ind_cmd_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "cpu_ind_rd_done",
		.reg_no = 670,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x40,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 1,
		.p_fields = g_smmu0_smmu0_cpu_ind_rd_done_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "cpu_ind_rdat0",
		.reg_no = 671,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x44,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 1,
		.p_fields = g_smmu0_smmu0_cpu_ind_rdat0_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "cpu_ind_rdat1",
		.reg_no = 672,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x48,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 1,
		.p_fields = g_smmu0_smmu0_cpu_ind_rdat1_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "cpu_ind_rdat2",
		.reg_no = 673,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x4c,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 1,
		.p_fields = g_smmu0_smmu0_cpu_ind_rdat2_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "cpu_ind_rdat3",
		.reg_no = 674,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x50,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 1,
		.p_fields = g_smmu0_smmu0_cpu_ind_rdat3_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "wr_arb_cpu_rdy",
		.reg_no = 676,
		.module_no = SMMU0,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_NUL_ARRAY,
		.addr = ZXDH_SYS_SE_SMMU0_BASE_ADDR + ZXDH_MODULE_SE_SMMU0_BASE_ADDR + 0x10c,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 0,
		.m_step = 0,
		.n_step = 0,
		.field_num = 1,
		.p_fields = g_smmu0_smmu0_wr_arb_cpu_rdy_reg,
		.p_write_fun = zxdh_np_se_smmu0_write,
		.p_read_fun = zxdh_np_se_smmu0_read,
	},
	{
		.reg_name = "info_queue_buf_space_left_0_127",
		.reg_no = 820,
		.module_no = DTB4K,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_UNI_ARRAY,
		.addr = ZXDH_SYS_DTB_BASE_ADDR + ZXDH_MODULE_DTB_ENQ_BASE_ADDR + 0xc,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 127 + 1,
		.m_step = 0,
		.n_step = 32,
		.field_num = 1,
		.p_fields = g_dtb4k_dtb_enq_info_queue_buf_space_left_0_127_reg,
		.p_write_fun = zxdh_np_write,
		.p_read_fun = zxdh_np_read,
	},
	{
		.reg_name = "cfg_epid_v_func_num_0_127",
		.reg_no = 821,
		.module_no = DTB4K,
		.flags = ZXDH_REG_FLAG_DIRECT,
		.array_type = ZXDH_REG_UNI_ARRAY,
		.addr = ZXDH_SYS_DTB_BASE_ADDR + ZXDH_MODULE_DTB_ENQ_BASE_ADDR + 0x10,
		.width = (32 / 8),
		.m_size = 0,
		.n_size = 127 + 1,
		.m_step = 0,
		.n_step = 32,
		.field_num = 7,
		.p_fields = g_dtb4k_dtb_enq_cfg_epid_v_func_num_0_127_reg,
		.p_write_fun = zxdh_np_write,
		.p_read_fun = zxdh_np_read,
	}
};

static uint32_t
zxdh_np_reg_get_reg_addr(uint32_t reg_no, uint32_t m_offset, uint32_t n_offset)
{
	uint32_t	 addr		= 0;
	ZXDH_REG_T  *p_reg_info = NULL;

	p_reg_info = &g_dpp_reg_info[reg_no];

	addr = p_reg_info->addr;

	if (p_reg_info->array_type & ZXDH_REG_UNI_ARRAY) {
		if (n_offset > (p_reg_info->n_size - 1))
			PMD_DRV_LOG(ERR, "reg n_offset is out of range, reg_no:%d, n:%d,"
				"size:%d", reg_no, n_offset, p_reg_info->n_size - 1);

		addr += n_offset * p_reg_info->n_step;
	} else if (p_reg_info->array_type & ZXDH_REG_BIN_ARRAY) {
		if ((n_offset > (p_reg_info->n_size - 1)) || (m_offset > (p_reg_info->m_size - 1)))
			PMD_DRV_LOG(ERR, "reg n_offset or m_offset is out of range, reg_no:%d,"
				"n:%d, n_size:%d, m:%d, m_size:%d,", reg_no, n_offset,
				p_reg_info->n_size - 1, m_offset, p_reg_info->m_size - 1);

		addr += m_offset * p_reg_info->m_step + n_offset * p_reg_info->n_step;
	}

	return addr;
}

static uint32_t
zxdh_np_dev_add(uint32_t  dev_id, ZXDH_DEV_TYPE_E dev_type,
		ZXDH_DEV_ACCESS_TYPE_E  access_type, uint64_t  pcie_addr,
		uint64_t  riscv_addr, uint64_t  dma_vir_addr,
		uint64_t  dma_phy_addr)
{
	ZXDH_DEV_CFG_T *p_dev_info = NULL;
	ZXDH_DEV_MGR_T *p_dev_mgr  = NULL;
	uint32_t i = 0;

	p_dev_mgr = &g_dev_mgr;
	if (!p_dev_mgr->is_init) {
		PMD_DRV_LOG(ERR, "ErrorCode[ 0x%x]: Device Manager is not init",
								 ZXDH_RC_DEV_MGR_NOT_INIT);
		return ZXDH_RC_DEV_MGR_NOT_INIT;
	}

	if (p_dev_mgr->p_dev_array[dev_id] != NULL) {
		/* device is already exist. */
		PMD_DRV_LOG(ERR, "Device is added again");
		p_dev_info = p_dev_mgr->p_dev_array[dev_id];
	} else {
		/* device is new. */
		p_dev_info = rte_malloc(NULL, sizeof(ZXDH_DEV_CFG_T), 0);
		if (p_dev_info == NULL) {
			PMD_DRV_LOG(ERR, "malloc memory failed");
			return ZXDH_PAR_CHK_POINT_NULL;
		}
		p_dev_mgr->p_dev_array[dev_id] = p_dev_info;
		p_dev_mgr->device_num++;
	}

	p_dev_info->device_id   = dev_id;
	p_dev_info->dev_type    = dev_type;
	p_dev_info->access_type = access_type;
	p_dev_info->pcie_addr   = pcie_addr;
	p_dev_info->riscv_addr   = riscv_addr;
	p_dev_info->dma_vir_addr = dma_vir_addr;
	p_dev_info->dma_phy_addr = dma_phy_addr;

	p_dev_info->p_pcie_write_fun = zxdh_np_dev_pcie_default_write;
	p_dev_info->p_pcie_read_fun  = zxdh_np_dev_pcie_default_read;

	zxdh_np_comm_spinlock_create(&p_dev_info->dtb_spinlock);

	for (i = 0; i < ZXDH_DTB_QUEUE_NUM_MAX; i++)
		zxdh_np_comm_spinlock_create(&p_dev_info->dtb_queue_spinlock[i]);

	return 0;
}

static uint32_t
zxdh_np_dev_agent_status_set(uint32_t dev_id, uint32_t agent_flag)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = NULL;
	ZXDH_DEV_CFG_T *p_dev_info = NULL;

	p_dev_mgr = &g_dev_mgr;
	p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	if (p_dev_info == NULL)
		return ZXDH_DEV_TYPE_INVALID;
	p_dev_info->agent_flag = agent_flag;

	return 0;
}

static void
zxdh_np_sdt_mgr_init(void)
{
	if (!g_sdt_mgr.is_init) {
		g_sdt_mgr.channel_num = 0;
		g_sdt_mgr.is_init = 1;
		memset(g_sdt_mgr.sdt_tbl_array, 0, ZXDH_DEV_CHANNEL_MAX *
			sizeof(ZXDH_SDT_SOFT_TABLE_T *));
	}
}

static uint32_t
zxdh_np_sdt_mgr_create(uint32_t dev_id)
{
	ZXDH_SDT_SOFT_TABLE_T *p_sdt_tbl_temp = NULL;
	ZXDH_SDT_MGR_T *p_sdt_mgr = NULL;

	p_sdt_mgr = ZXDH_SDT_MGR_PTR_GET();

	if (ZXDH_SDT_SOFT_TBL_GET(dev_id) == NULL) {
		p_sdt_tbl_temp = rte_malloc(NULL, sizeof(ZXDH_SDT_SOFT_TABLE_T), 0);

		p_sdt_tbl_temp->device_id = dev_id;
		memset(p_sdt_tbl_temp->sdt_array, 0, ZXDH_DEV_SDT_ID_MAX * sizeof(ZXDH_SDT_ITEM_T));

		ZXDH_SDT_SOFT_TBL_GET(dev_id) = p_sdt_tbl_temp;

		p_sdt_mgr->channel_num++;
	} else {
		PMD_DRV_LOG(ERR, "called repeatedly!");
		return 1;
	}

	return 0;
}

static uint32_t
zxdh_np_sdt_init(uint32_t dev_num, uint32_t *dev_id_array)
{
	uint32_t rc;
	uint32_t i;

	zxdh_np_sdt_mgr_init();

	for (i = 0; i < dev_num; i++) {
		rc = zxdh_np_sdt_mgr_create(dev_id_array[i]);
		ZXDH_COMM_CHECK_RC(rc, "zxdh_sdt_mgr_create");
	}

	return rc;
}

static void
zxdh_np_ppu_parse_cls_bitmap(uint32_t dev_id,
								uint32_t bitmap)
{
	uint32_t cls_id;
	uint32_t mem_id;
	uint32_t cls_use;
	uint32_t instr_mem;

	for (cls_id = 0; cls_id < ZXDH_PPU_CLUSTER_NUM; cls_id++) {
		cls_use = (bitmap >> cls_id) & 0x1;
		g_ppu_cls_bit_map[dev_id].cls_use[cls_id] = cls_use;
	}

	for (mem_id = 0; mem_id < ZXDH_PPU_INSTR_MEM_NUM; mem_id++) {
		instr_mem = (bitmap >> (mem_id * 2)) & 0x3;
		g_ppu_cls_bit_map[dev_id].instr_mem[mem_id] = ((instr_mem > 0) ? 1 : 0);
	}
}

static void
zxdh_np_agent_msg_prt(uint8_t type, uint32_t rtn)
{
	switch (rtn) {
	case ZXDH_RC_CTRLCH_MSG_LEN_ZERO:
		PMD_DRV_LOG(ERR, "type[%u]:msg len is zero!", type);
		break;
	case ZXDH_RC_CTRLCH_MSG_PRO_ERR:
		PMD_DRV_LOG(ERR, "type[%u]:msg process error!", type);
		break;
	case ZXDH_RC_CTRLCH_MSG_TYPE_NOT_SUPPORT:
		PMD_DRV_LOG(ERR, "type[%u]:fw not support the msg!", type);
		break;
	case ZXDH_RC_CTRLCH_MSG_OPER_NOT_SUPPORT:
		PMD_DRV_LOG(ERR, "type[%u]:fw not support opr of the msg!", type);
		break;
	case ZXDH_RC_CTRLCH_MSG_DROP:
		PMD_DRV_LOG(ERR, "type[%u]:fw not support,drop msg!", type);
		break;
	default:
		break;
	}
}

static uint32_t
zxdh_np_agent_bar_msg_check(uint32_t dev_id, ZXDH_AGENT_CHANNEL_MSG_T *p_msg)
{
	uint8_t type = 0;
	uint32_t bar_msg_num = 0;

	type = *((uint8_t *)(p_msg->msg) + 1);
	if (type != ZXDH_PCIE_BAR_MSG) {
		zxdh_np_dev_fw_bar_msg_num_get(dev_id, &bar_msg_num);
		if (type >= bar_msg_num) {
			PMD_DRV_LOG(ERR, "type[%u] > fw_bar_msg_num[%u]!", type, bar_msg_num);
			return ZXDH_RC_CTRLCH_MSG_TYPE_NOT_SUPPORT;
		}
	}

	return ZXDH_OK;
}

static uint32_t
zxdh_np_agent_channel_sync_send(uint32_t dev_id,
				ZXDH_AGENT_CHANNEL_MSG_T *p_msg,
				uint32_t *p_data,
				uint32_t rep_len)
{
	uint32_t ret = ZXDH_OK;
	uint32_t vport = 0;
	struct zxdh_pci_bar_msg in = {0};
	struct zxdh_msg_recviver_mem result = {0};
	uint32_t *recv_buffer = NULL;
	uint8_t *reply_ptr = NULL;
	uint16_t reply_msg_len = 0;
	uint64_t agent_addr = 0;

	ret = zxdh_np_agent_bar_msg_check(dev_id, p_msg);
	if (ret != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "zxdh_np_agent_bar_msg_check failed!");
		return ret;
	}

	zxdh_np_dev_vport_get(dev_id, &vport);
	zxdh_np_dev_agent_addr_get(dev_id, &agent_addr);

	if (ZXDH_IS_PF(vport))
		in.src = ZXDH_MSG_CHAN_END_PF;
	else
		in.src = ZXDH_MSG_CHAN_END_VF;

	in.virt_addr = agent_addr;
	in.payload_addr = p_msg->msg;
	in.payload_len = p_msg->msg_len;
	in.dst = ZXDH_MSG_CHAN_END_RISC;
	in.module_id = ZXDH_BAR_MDOULE_NPSDK;

	recv_buffer = (uint32_t *)rte_zmalloc(NULL, rep_len + ZXDH_CHANNEL_REPS_LEN, 0);
	if (recv_buffer == NULL) {
		PMD_DRV_LOG(ERR, "malloc memory failed");
		return ZXDH_PAR_CHK_POINT_NULL;
	}

	result.buffer_len = rep_len + ZXDH_CHANNEL_REPS_LEN;
	result.recv_buffer = recv_buffer;

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret == ZXDH_BAR_MSG_OK) {
		reply_ptr = (uint8_t *)(result.recv_buffer);
		if (*reply_ptr == 0XFF) {
			reply_msg_len = *(uint16_t *)(reply_ptr + 1);
			memcpy(p_data, reply_ptr + 4,
				((reply_msg_len > rep_len) ? rep_len : reply_msg_len));
		} else {
			PMD_DRV_LOG(ERR, "Message not replied");
		}
	} else {
		PMD_DRV_LOG(ERR, "Error[0x%x], bar msg send failed!", ret);
	}

	rte_free(recv_buffer);
	return ret;
}

static uint32_t
zxdh_np_agent_channel_reg_sync_send(uint32_t dev_id,
	ZXDH_AGENT_CHANNEL_REG_MSG_T *p_msg, uint32_t *p_data, uint32_t rep_len)
{
	uint32_t ret = ZXDH_OK;
	ZXDH_COMM_CHECK_DEV_POINT(dev_id, p_msg);
	ZXDH_AGENT_CHANNEL_MSG_T agent_msg = {
		.msg = (void *)p_msg,
		.msg_len = sizeof(ZXDH_AGENT_CHANNEL_REG_MSG_T),
	};

	ret = zxdh_np_agent_channel_sync_send(dev_id, &agent_msg, p_data, rep_len);
	if (ret != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "zxdh_np_agent_channel_sync_send failed");
		return ZXDH_ERR;
	}

	ret = *p_data;
	if (ret != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "zxdh_np_agent_channel_sync_send failed in buffer");
		return ZXDH_ERR;
	}

	return ret;
}

static uint32_t
zxdh_np_agent_channel_pcie_bar_request(uint32_t dev_id,
									uint32_t *p_bar_msg_num)
{
	uint32_t rc = ZXDH_OK;
	uint32_t rsp_buff[2] = {0};
	uint32_t msg_result = 0;
	uint32_t bar_msg_num = 0;
	ZXDH_AGENT_PCIE_BAR_MSG_T msgcfg = {
		.dev_id = 0,
		.type   = ZXDH_PCIE_BAR_MSG,
		.oper   = ZXDH_BAR_MSG_NUM_REQ,
	};
	ZXDH_AGENT_CHANNEL_MSG_T agent_msg = {
		.msg = (void *)&msgcfg,
		.msg_len = sizeof(ZXDH_AGENT_PCIE_BAR_MSG_T),
	};

	rc = zxdh_np_agent_channel_sync_send(dev_id, &agent_msg, rsp_buff, sizeof(rsp_buff));
	if (rc != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "zxdh_np_agent_channel_sync_send failed!");
		return rc;
	}

	msg_result = rsp_buff[0];
	bar_msg_num = rsp_buff[1];

	zxdh_np_agent_msg_prt(msgcfg.type, msg_result);

	*p_bar_msg_num = bar_msg_num;

	return msg_result;
}

static uint32_t
zxdh_np_agent_channel_reg_read(uint32_t dev_id,
							uint32_t reg_type,
							uint32_t reg_no,
							uint32_t reg_width,
							uint32_t addr,
							uint32_t *p_data)
{
	uint32_t ret = 0;
	ZXDH_AGENT_CHANNEL_REG_MSG_T msgcfg = {
		.dev_id  = 0,
		.type    = ZXDH_REG_MSG,
		.subtype = reg_type,
		.oper    = ZXDH_RD,
		.reg_no  = reg_no,
		.addr	 = addr,
		.val_len = reg_width / 4,
	};

	uint32_t resp_len = reg_width + 4;
	uint8_t *resp_buffer = (uint8_t *)rte_zmalloc(NULL, resp_len, 0);
	if (resp_buffer == NULL) {
		PMD_DRV_LOG(ERR, "malloc memory failed");
		return ZXDH_PAR_CHK_POINT_NULL;
	}

	ret = zxdh_np_agent_channel_reg_sync_send(dev_id,
		&msgcfg, (uint32_t *)resp_buffer, resp_len);
	if (ret != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "dev id %d reg_no %d send agent read failed.", dev_id, reg_no);
		rte_free(resp_buffer);
		return ZXDH_ERR;
	}

	if (*((uint32_t *)resp_buffer) != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "dev id %d reg_no %d agent read resp err %d .",
			dev_id, reg_no, *((uint32_t *)resp_buffer));
		rte_free(resp_buffer);
		return ZXDH_ERR;
	}

	memcpy(p_data, resp_buffer + 4, reg_width);

	rte_free(resp_buffer);

	return ret;
}

static uint32_t
zxdh_np_agent_channel_reg_write(uint32_t dev_id,
							uint32_t reg_type,
							uint32_t reg_no,
							uint32_t reg_width,
							uint32_t addr,
							uint32_t *p_data)
{
	uint32_t ret = ZXDH_OK;
	ZXDH_AGENT_CHANNEL_REG_MSG_T msgcfg = {
		.dev_id  = 0,
		.type    = ZXDH_REG_MSG,
		.subtype = reg_type,
		.oper    = ZXDH_WR,
		.reg_no  = reg_no,
		.addr	 = addr,
		.val_len = reg_width / 4,
	};

	memcpy(msgcfg.val, p_data, reg_width);

	uint32_t resp_len = reg_width + 4;
	uint8_t *resp_buffer = (uint8_t *)rte_zmalloc(NULL, resp_len, 0);
	if (resp_buffer == NULL) {
		PMD_DRV_LOG(ERR, "malloc memory failed");
		return ZXDH_PAR_CHK_POINT_NULL;
	}

	ret = zxdh_np_agent_channel_reg_sync_send(dev_id,
		&msgcfg, (uint32_t *)resp_buffer, resp_len);

	if (ret != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "dev id %d reg_no %d send agent write failed.", dev_id, reg_no);
		rte_free(resp_buffer);
		return ZXDH_ERR;
	}

	if (*((uint32_t *)resp_buffer) != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "dev id %d reg_no %d agent write resp err %d .",
			dev_id, reg_no, *((uint32_t *)resp_buffer));
		rte_free(resp_buffer);
		return ZXDH_ERR;
	}

	memcpy(p_data, resp_buffer + 4, reg_width);

	rte_free(resp_buffer);

	return ret;
}

static uint32_t
zxdh_np_agent_channel_dtb_sync_send(uint32_t dev_id,
							ZXDH_AGENT_CHANNEL_DTB_MSG_T *p_msg,
							uint32_t *p_data,
							uint32_t rep_len)
{
	uint32_t ret = ZXDH_OK;

	ZXDH_AGENT_CHANNEL_MSG_T agent_msg = {0};
	agent_msg.msg = (void *)p_msg;
	agent_msg.msg_len = sizeof(ZXDH_AGENT_CHANNEL_DTB_MSG_T);

	ret = zxdh_np_agent_channel_sync_send(dev_id, &agent_msg, p_data, rep_len);
	if (ret != ZXDH_OK) {
		PMD_DRV_LOG(ERR, "zxdh_np_agent_channel_sync_send failed");
		return ZXDH_ERR;
	}

	return ZXDH_OK;
}

static uint32_t
zxdh_np_agent_channel_dtb_queue_request(uint32_t dev_id,
									char p_name[32],
									uint32_t vport_info,
									uint32_t *p_queue_id)
{
	uint32_t rc = ZXDH_OK;

	uint32_t rsp_buff[2] = {0};
	uint32_t msg_result = 0;
	uint32_t queue_id = 0;
	ZXDH_AGENT_CHANNEL_DTB_MSG_T msgcfg = {
		.dev_id  = 0,
		.type    = ZXDH_DTB_MSG,
		.oper    = ZXDH_QUEUE_REQUEST,
		.vport   = vport_info,
	};
	memcpy(msgcfg.name, p_name, strnlen(p_name, ZXDH_PORT_NAME_MAX));

	PMD_DRV_LOG(DEBUG, "msgcfg.name=%s", msgcfg.name);

	rc = zxdh_np_agent_channel_dtb_sync_send(dev_id, &msgcfg, rsp_buff, sizeof(rsp_buff));
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_agent_channel_dtb_sync_send");

	msg_result = rsp_buff[0];
	queue_id = rsp_buff[1];

	PMD_DRV_LOG(DEBUG, "dev_id: %d, msg_result: %d", dev_id, msg_result);
	PMD_DRV_LOG(DEBUG, "dev_id: %d, queue_id: %d", dev_id, queue_id);

	*p_queue_id = queue_id;

	return msg_result;
}

static uint32_t
zxdh_np_agent_channel_dtb_queue_release(uint32_t dev_id,
								char p_name[32],
								__rte_unused uint32_t queue_id)
{
	uint32_t rc = ZXDH_OK;

	uint32_t msg_result = 0;
	uint32_t rsp_buff[2] = {0};
	ZXDH_AGENT_CHANNEL_DTB_MSG_T msgcfg = {
		.dev_id  = 0,
		.type    = ZXDH_DTB_MSG,
		.oper    = ZXDH_QUEUE_RELEASE,
		.queue_id = queue_id,
	};

	memcpy(msgcfg.name, p_name, strnlen(p_name, ZXDH_PORT_NAME_MAX));

	rc = zxdh_np_agent_channel_dtb_sync_send(dev_id, &msgcfg, rsp_buff, sizeof(rsp_buff));
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_agent_channel_dtb_sync_send");

	msg_result = rsp_buff[0];
	PMD_DRV_LOG(DEBUG, "msg_result: %d", msg_result);

	return msg_result;
}

static ZXDH_DTB_MGR_T *
zxdh_np_dtb_mgr_get(uint32_t dev_id)
{
	if (dev_id >= ZXDH_DEV_CHANNEL_MAX)
		return NULL;
	else
		return p_dpp_dtb_mgr[dev_id];
}

static uint32_t
zxdh_np_dtb_mgr_create(uint32_t dev_id)
{
	if (p_dpp_dtb_mgr[dev_id] != NULL) {
		PMD_DRV_LOG(ERR, "ErrorCode[0x%x]: Dma Manager"
			" is exist!!!", ZXDH_RC_DTB_MGR_EXIST);
		return ZXDH_RC_DTB_MGR_EXIST;
	}

	p_dpp_dtb_mgr[dev_id] = (ZXDH_DTB_MGR_T *)rte_zmalloc(NULL, sizeof(ZXDH_DTB_MGR_T), 0);
	if (p_dpp_dtb_mgr[dev_id] == NULL) {
		PMD_DRV_LOG(ERR, "malloc memory failed");
		return ZXDH_PAR_CHK_POINT_NULL;
	}

	return ZXDH_OK;
}

static uint32_t
zxdh_np_dtb_soft_init(uint32_t dev_id)
{
	ZXDH_DTB_MGR_T *p_dtb_mgr = NULL;

	if (dev_id >= ZXDH_DEV_CHANNEL_MAX)
		return 1;

	p_dtb_mgr = zxdh_np_dtb_mgr_get(dev_id);
	if (p_dtb_mgr == NULL) {
		zxdh_np_dtb_mgr_create(dev_id);

		p_dtb_mgr = zxdh_np_dtb_mgr_get(dev_id);
		if (p_dtb_mgr == NULL)
			return ZXDH_RC_DTB_MGR_NOT_EXIST;
	}

	return 0;
}

static uint32_t
zxdh_np_base_soft_init(uint32_t dev_id, ZXDH_SYS_INIT_CTRL_T *p_init_ctrl)
{
	uint32_t dev_id_array[ZXDH_DEV_CHANNEL_MAX] = {0};
	uint32_t rt;
	uint32_t access_type;
	uint32_t agent_flag;

	rt = zxdh_np_dev_init();
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rt, "zxdh_dev_init");

	if (p_init_ctrl->flags & ZXDH_INIT_FLAG_ACCESS_TYPE)
		access_type = ZXDH_DEV_ACCESS_TYPE_RISCV;
	else
		access_type = ZXDH_DEV_ACCESS_TYPE_PCIE;

	if (p_init_ctrl->flags & ZXDH_INIT_FLAG_AGENT_FLAG)
		agent_flag = ZXDH_DEV_AGENT_ENABLE;
	else
		agent_flag = ZXDH_DEV_AGENT_DISABLE;

	rt = zxdh_np_dev_add(dev_id,
					 p_init_ctrl->device_type,
					 access_type,
					 p_init_ctrl->pcie_vir_baddr,
					 p_init_ctrl->riscv_vir_baddr,
					 p_init_ctrl->dma_vir_baddr,
					 p_init_ctrl->dma_phy_baddr);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rt, "zxdh_dev_add");

	rt = zxdh_np_dev_agent_status_set(dev_id, agent_flag);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rt, "zxdh_dev_agent_status_set");

	dev_id_array[0] = dev_id;
	rt = zxdh_np_sdt_init(1, dev_id_array);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rt, "zxdh_sdt_init");

	zxdh_np_ppu_parse_cls_bitmap(dev_id, ZXDH_PPU_CLS_ALL_START);

	rt = zxdh_np_dtb_soft_init(dev_id);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rt, "zxdh_dtb_soft_init");

	return rt;
}

static void
zxdh_np_dev_vport_set(uint32_t dev_id, uint32_t vport)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = NULL;
	ZXDH_DEV_CFG_T *p_dev_info = NULL;

	p_dev_mgr =  &g_dev_mgr;
	p_dev_info = p_dev_mgr->p_dev_array[dev_id];
	p_dev_info->vport = vport;
}

static void
zxdh_np_dev_agent_addr_set(uint32_t dev_id, uint64_t agent_addr)
{
	ZXDH_DEV_MGR_T *p_dev_mgr = NULL;
	ZXDH_DEV_CFG_T *p_dev_info = NULL;

	p_dev_mgr =  &g_dev_mgr;
	p_dev_info = p_dev_mgr->p_dev_array[dev_id];
	p_dev_info->agent_addr = agent_addr;
}

static uint64_t
zxdh_np_addr_calc(uint64_t pcie_vir_baddr, uint32_t bar_offset)
{
	uint64_t np_addr;

	np_addr = ((pcie_vir_baddr + bar_offset) > ZXDH_PCIE_NP_MEM_SIZE)
				? (pcie_vir_baddr + bar_offset - ZXDH_PCIE_NP_MEM_SIZE) : 0;

	return np_addr;
}

static uint64_t
zxdh_np_fw_compatible_addr_calc(uint64_t pcie_vir_baddr, uint64_t compatible_offset)
{
	return (pcie_vir_baddr + compatible_offset);
}

static void
zxdh_np_pf_fw_compatible_addr_set(uint32_t dev_id, uint64_t pcie_vir_baddr)
{
	uint64_t compatible_offset = ZXDH_DPU_NO_DEBUG_PF_COMPAT_REG_OFFSET;
	uint64_t compatible_addr = 0;

	compatible_addr = zxdh_np_fw_compatible_addr_calc(pcie_vir_baddr, compatible_offset);

	g_np_fw_compat_addr[dev_id] = compatible_addr;
}

static void
zxdh_np_fw_compatible_addr_get(uint32_t dev_id, uint64_t *p_compatible_addr)
{
	*p_compatible_addr = g_np_fw_compat_addr[dev_id];
}

static void
zxdh_np_fw_version_data_read(uint64_t compatible_base_addr,
			ZXDH_VERSION_COMPATIBLE_REG_T *p_fw_version_data, uint32_t module_id)
{
	void *fw_addr = NULL;
	uint64_t module_compatible_addr = 0;

	module_compatible_addr = compatible_base_addr +
		sizeof(ZXDH_VERSION_COMPATIBLE_REG_T) * (module_id - 1);

	fw_addr = (void *)module_compatible_addr;

	memcpy(p_fw_version_data, fw_addr, sizeof(ZXDH_VERSION_COMPATIBLE_REG_T));
}

static void
zxdh_np_fw_version_compatible_data_get(uint32_t dev_id,
			ZXDH_VERSION_COMPATIBLE_REG_T *p_version_compatible_value,
			uint32_t module_id)
{
	uint64_t compatible_addr = 0;

	zxdh_np_fw_compatible_addr_get(dev_id, &compatible_addr);

	zxdh_np_fw_version_data_read(compatible_addr, p_version_compatible_value, module_id);
}

static uint32_t
zxdh_np_np_sdk_version_compatible_check(uint32_t dev_id)
{
	ZXDH_VERSION_COMPATIBLE_REG_T fw_version = {0};

	zxdh_np_fw_version_compatible_data_get(dev_id, &fw_version, ZXDH_NPSDK_COMPAT_ITEM_ID);

	if (fw_version.version_compatible_item != ZXDH_NPSDK_COMPAT_ITEM_ID) {
		PMD_DRV_LOG(ERR, "version_compatible_item is not DH_NPSDK.");
		return ZXDH_ERR;
	}

	if (g_np_sdk_version.major != fw_version.major) {
		PMD_DRV_LOG(ERR, "dh_npsdk major:%hhu: is not match fw:%hhu!",
			g_np_sdk_version.major, fw_version.major);
		return ZXDH_ERR;
	}

	if (g_np_sdk_version.fw_minor > fw_version.fw_minor) {
		PMD_DRV_LOG(ERR, "dh_npsdk fw_minor:%hhu is higher than fw:%hhu!",
			g_np_sdk_version.fw_minor, fw_version.fw_minor);
		return ZXDH_ERR;
	}

	if (g_np_sdk_version.drv_minor < fw_version.drv_minor) {
		PMD_DRV_LOG(ERR, "dh_npsdk drv_minor:%hhu is lower than fw:%hhu!",
			g_np_sdk_version.drv_minor, fw_version.drv_minor);
		return ZXDH_ERR;
	}

	PMD_DRV_LOG(INFO, "dh_npsdk compatible check success!");

	return ZXDH_OK;
}

static uint32_t
zxdh_np_pcie_bar_msg_num_get(uint32_t dev_id, uint32_t *p_bar_msg_num)
{
	uint32_t rc = ZXDH_OK;
	ZXDH_SPINLOCK_T *p_dtb_spinlock = NULL;
	ZXDH_DEV_SPINLOCK_TYPE_E spinlock = ZXDH_DEV_SPINLOCK_T_DTB;

	rc = zxdh_np_dev_opr_spinlock_get(dev_id, (uint32_t)spinlock, &p_dtb_spinlock);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dev_opr_spinlock_get");

	zxdh_np_comm_spinlock_lock(p_dtb_spinlock);
	rc = zxdh_np_agent_channel_pcie_bar_request(dev_id, p_bar_msg_num);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_agent_channel_pcie_bar_request");
	zxdh_np_comm_spinlock_unlock(p_dtb_spinlock);

	return rc;
}

static uint32_t
zxdh_np_comm_read_bits(uint8_t *p_base, uint32_t base_size_bit,
		uint32_t *p_data, uint32_t start_bit, uint32_t end_bit)
{
	uint32_t start_byte_index;
	uint32_t end_byte_index;
	uint32_t byte_num;
	uint32_t buffer_size;
	uint32_t len;

	if (0 != (base_size_bit % 8))
		return 1;

	if (start_bit > end_bit)
		return 1;

	if (base_size_bit < end_bit)
		return 1;

	len = end_bit - start_bit + 1;
	buffer_size = base_size_bit / 8;
	while (0 != (buffer_size & (buffer_size - 1)))
		buffer_size += 1;

	*p_data = 0;
	end_byte_index     = (end_bit    >> 3);
	start_byte_index   = (start_bit  >> 3);

	if (start_byte_index == end_byte_index) {
		*p_data = (uint32_t)(((p_base[start_byte_index] >> (7U - (end_bit & 7)))
			& (0xff >> (8U - len))) & 0xff);
		return 0;
	}

	if (start_bit & 7) {
		*p_data = (p_base[start_byte_index] & (0xff >> (start_bit & 7))) & UINT8_MAX;
		start_byte_index++;
	}

	for (byte_num = start_byte_index; byte_num < end_byte_index; byte_num++) {
		*p_data <<= 8;
		*p_data  += p_base[byte_num];
	}

	*p_data <<= 1 + (end_bit & 7);
	*p_data  += ((p_base[byte_num & (buffer_size - 1)] & (0xff << (7 - (end_bit  & 7)))) >>
		(7 - (end_bit  & 7))) & 0xff;

	return 0;
}

static uint32_t
zxdh_np_comm_read_bits_ex(uint8_t *p_base, uint32_t base_size_bit,
		uint32_t *p_data, uint32_t msb_start_pos, uint32_t len)
{
	uint32_t rtn;

	rtn = zxdh_np_comm_read_bits(p_base,
				base_size_bit,
				p_data,
				(base_size_bit - 1 - msb_start_pos),
				(base_size_bit - 1 - msb_start_pos + len - 1));
	return rtn;
}

static uint32_t
zxdh_np_reg_read(uint32_t dev_id, uint32_t reg_no,
		uint32_t m_offset, uint32_t n_offset, void *p_data)
{
	uint32_t p_buff[ZXDH_REG_DATA_MAX] = {0};
	ZXDH_REG_T *p_reg_info = &g_dpp_reg_info[reg_no];
	ZXDH_FIELD_T *p_field_info = p_reg_info->p_fields;
	uint32_t rc = 0;
	uint32_t i;
	uint32_t addr = 0;
	uint32_t reg_module = p_reg_info->module_no;
	uint32_t reg_width = p_reg_info->width;
	uint32_t reg_real_no = p_reg_info->reg_no;
	uint32_t reg_type = p_reg_info->flags;

	addr = zxdh_np_reg_get_reg_addr(reg_no, m_offset, n_offset);

	if (reg_module == DTB4K) {
		rc = p_reg_info->p_read_fun(dev_id, addr, p_buff);
		ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "p_reg_info->p_read_fun");
	} else {
		rc = zxdh_np_agent_channel_reg_read(dev_id,
			reg_type, reg_real_no, reg_width, addr, p_buff);
		ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_agent_channel_reg_read");
	}

	if (!zxdh_np_comm_is_big_endian()) {
		for (i = 0; i < p_reg_info->width / 4; i++) {
			PMD_DRV_LOG(DEBUG, "data = 0x%08x.", p_buff[i]);
			p_buff[i] = ZXDH_COMM_CONVERT32(p_buff[i]);
		}
	}

	for (i = 0; i < p_reg_info->field_num; i++) {
		rc = zxdh_np_comm_read_bits_ex((uint8_t *)p_buff,
								p_reg_info->width * 8,
								(uint32_t *)p_data + i,
								p_field_info[i].msb_pos,
								p_field_info[i].len);
		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_np_comm_read_bits_ex");
		PMD_DRV_LOG(ERR, "dev_id %d(%d)(%d)is ok!", dev_id, m_offset, n_offset);
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_queue_vm_info_get(uint32_t dev_id,
		uint32_t queue_id,
		ZXDH_DTB_QUEUE_VM_INFO_T *p_vm_info)
{
	uint32_t rc = 0;
	uint32_t dtb_epid_v_func_reg = ZXDH_SYS_DTB_BASE_ADDR +
		ZXDH_MODULE_DTB_ENQ_BASE_ADDR + 0x0010;
	uint32_t epid_v_func = 0;

	rc = zxdh_np_dev_read_channel(dev_id, dtb_epid_v_func_reg + queue_id * 32, 1, &epid_v_func);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dev_read_channel");

	p_vm_info->dbi_en = (epid_v_func >> 31 & 0x1);
	p_vm_info->queue_en = (epid_v_func >> 30 & 0x1);
	p_vm_info->epid = (epid_v_func >> 24 & 0xF);
	p_vm_info->vfunc_num = (epid_v_func >> 16 & 0xFF);
	p_vm_info->vector = (epid_v_func >> 8 & 0x7);
	p_vm_info->func_num = (epid_v_func >> 5 & 0x7);
	p_vm_info->vfunc_active = (epid_v_func & 0x1);

	return rc;
}

static uint32_t
zxdh_np_comm_write_bits(uint8_t *p_base, uint32_t base_size_bit,
			uint32_t data, uint32_t start_bit, uint32_t end_bit)
{
	uint32_t start_byte_index;
	uint32_t end_byte_index;
	uint8_t mask_value;
	uint32_t byte_num;
	uint32_t buffer_size;

	if (0 != (base_size_bit % 8))
		return 1;

	if (start_bit > end_bit)
		return 1;

	if (base_size_bit < end_bit)
		return 1;

	buffer_size = base_size_bit / 8;

	while (0 != (buffer_size & (buffer_size - 1)))
		buffer_size += 1;

	end_byte_index     = (end_bit    >> 3);
	start_byte_index   = (start_bit  >> 3);

	if (start_byte_index == end_byte_index) {
		mask_value  = ((0xFE << (7 - (start_bit & 7))) & 0xff);
		mask_value |= (((1 << (7 - (end_bit  & 7))) - 1) & 0xff);
		p_base[end_byte_index] &= mask_value;
		p_base[end_byte_index] |= (((data << (7 - (end_bit & 7)))) & 0xff);
		return 0;
	}

	if (7 != (end_bit & 7)) {
		mask_value = ((0x7f >> (end_bit  & 7)) & 0xff);
		p_base[end_byte_index] &= mask_value;
		p_base[end_byte_index] |= ((data << (7 - (end_bit & 7))) & 0xff);
		end_byte_index--;
		data >>= 1 + (end_bit  & 7);
	}

	for (byte_num = end_byte_index; byte_num > start_byte_index; byte_num--) {
		p_base[byte_num & (buffer_size - 1)] = data & 0xff;
		data >>= 8;
	}

	mask_value        = ((0xFE << (7 - (start_bit  & 7))) & 0xff);
	p_base[byte_num] &= mask_value;
	p_base[byte_num] |= data;

	return 0;
}

static uint32_t
zxdh_np_comm_write_bits_ex(uint8_t *p_base,
		uint32_t base_size_bit,
		uint32_t data,
		uint32_t msb_start_pos,
		uint32_t len)
{
	uint32_t rtn;

	rtn = zxdh_np_comm_write_bits(p_base,
				base_size_bit,
				data,
				(base_size_bit - 1 - msb_start_pos),
				(base_size_bit - 1 - msb_start_pos + len - 1));

	return rtn;
}

static uint32_t
zxdh_np_reg_write(uint32_t dev_id, uint32_t reg_no,
			uint32_t m_offset, uint32_t n_offset, void *p_data)
{
	uint32_t p_buff[ZXDH_REG_DATA_MAX] = {0};
	ZXDH_REG_T *p_reg_info = &g_dpp_reg_info[reg_no];
	ZXDH_FIELD_T *p_field_info = p_reg_info->p_fields;
	uint32_t temp_data;
	uint32_t rc = ZXDH_OK;
	uint32_t i;
	uint32_t addr = 0;
	uint32_t reg_module = p_reg_info->module_no;
	uint32_t reg_width = p_reg_info->width;
	uint32_t reg_type = p_reg_info->flags;
	uint32_t reg_real_no = p_reg_info->reg_no;

	for (i = 0; i < p_reg_info->field_num; i++) {
		if (p_field_info[i].len <= 32) {
			temp_data = *((uint32_t *)p_data + i) & ZXDH_COMM_GET_BIT_MASK(uint32_t,
				p_field_info[i].len);
			rc = zxdh_np_comm_write_bits_ex((uint8_t *)p_buff,
								p_reg_info->width * 8,
								temp_data,
								p_field_info[i].msb_pos,
								p_field_info[i].len);
			ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_comm_write_bits_ex");
		}
	}

	PMD_DRV_LOG(DEBUG, "zxdh_np_comm_write_bits_ex data = 0x%08x.", p_buff[0]);

	if (!zxdh_np_comm_is_big_endian()) {
		for (i = 0; i < p_reg_info->width / 4; i++) {
			p_buff[i] = ZXDH_COMM_CONVERT32(p_buff[i]);

			PMD_DRV_LOG(DEBUG, "ZXDH_COMM_CONVERT32 data = 0x%08x.",
				p_buff[i]);
		}
	}

	addr = zxdh_np_reg_get_reg_addr(reg_no, m_offset, n_offset);

	PMD_DRV_LOG(DEBUG, "reg_no = %d. m_offset = %d n_offset = %d",
		reg_no, m_offset, n_offset);
	PMD_DRV_LOG(DEBUG, "baseaddr = 0x%08x.", addr);

	if (reg_module == DTB4K) {
		rc = p_reg_info->p_write_fun(dev_id, addr, p_buff);
		ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "p_reg_info->p_write_fun");
	} else {
		rc = zxdh_np_agent_channel_reg_write(dev_id,
			reg_type, reg_real_no, reg_width, addr, p_buff);
		ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_agent_channel_reg_write");
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_queue_vm_info_set(uint32_t dev_id,
		uint32_t queue_id,
		ZXDH_DTB_QUEUE_VM_INFO_T *p_vm_info)
{
	uint32_t rc = 0;
	ZXDH_DTB4K_DTB_ENQ_CFG_EPID_V_FUNC_NUM_0_127_T vm_info = {0};

	vm_info.dbi_en = p_vm_info->dbi_en;
	vm_info.queue_en = p_vm_info->queue_en;
	vm_info.cfg_epid = p_vm_info->epid;
	vm_info.cfg_vector = p_vm_info->vector;
	vm_info.cfg_vfunc_num = p_vm_info->vfunc_num;
	vm_info.cfg_func_num = p_vm_info->func_num;
	vm_info.cfg_vfunc_active = p_vm_info->vfunc_active;

	rc = zxdh_np_reg_write(dev_id, ZXDH_DTB_CFG_EPID_V_FUNC_NUM,
						0, queue_id, &vm_info);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_reg_write");

	return rc;
}

static uint32_t
zxdh_np_dtb_queue_unused_item_num_get(uint32_t dev_id,
						uint32_t queue_id,
						uint32_t *p_item_num)
{
	uint32_t rc;

	rc = zxdh_np_reg_read(dev_id, ZXDH_DTB_INFO_QUEUE_BUF_SPACE,
		0, queue_id, p_item_num);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_reg_read");
	return rc;
}

static uint32_t
zxdh_np_dtb_queue_id_free(uint32_t dev_id,
					uint32_t queue_id)
{
	uint32_t item_num = 0;
	ZXDH_DTB_MGR_T *p_dtb_mgr = NULL;
	uint32_t rc;

	p_dtb_mgr = p_dpp_dtb_mgr[dev_id];
	if (p_dtb_mgr == NULL)
		return 1;

	rc = zxdh_np_dtb_queue_unused_item_num_get(dev_id, queue_id, &item_num);

	p_dtb_mgr->queue_info[queue_id].init_flag = 0;
	p_dtb_mgr->queue_info[queue_id].vport = 0;
	p_dtb_mgr->queue_info[queue_id].vector = 0;

	return rc;
}

static uint32_t
zxdh_np_dtb_queue_request(uint32_t dev_id, char p_name[32],
					uint16_t vport, uint32_t *p_queue_id)
{
	uint32_t rc = ZXDH_OK;
	uint32_t queue_id = 0xFF;
	ZXDH_SPINLOCK_T *p_dtb_spinlock = NULL;
	ZXDH_DEV_SPINLOCK_TYPE_E spinlock = ZXDH_DEV_SPINLOCK_T_DTB;
	uint32_t vport_info = (uint32_t)vport;

	rc = zxdh_np_dev_opr_spinlock_get(dev_id, (uint32_t)spinlock, &p_dtb_spinlock);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dev_opr_spinlock_get");

	zxdh_np_comm_spinlock_lock(p_dtb_spinlock);

	rc = zxdh_np_agent_channel_dtb_queue_request(dev_id, p_name, vport_info, &queue_id);
	if (rc == ZXDH_RC_DTB_QUEUE_RES_EMPTY) {
		PMD_DRV_LOG(ERR, "dtb queue is locked full.");
		zxdh_np_comm_spinlock_unlock(p_dtb_spinlock);
		return ZXDH_RC_DTB_QUEUE_RES_EMPTY;
	}

	zxdh_np_comm_spinlock_unlock(p_dtb_spinlock);

	PMD_DRV_LOG(DEBUG, "dtb request queue is %d.", queue_id);

	*p_queue_id = queue_id;

	PMD_DRV_LOG(INFO, "dev_id %d vport 0x%x name %s queue_id %d done.",
		dev_id, vport_info, p_name, queue_id);

	return rc;
}

static uint32_t
zxdh_np_dtb_queue_release(uint32_t devid,
		char pname[32],
		uint32_t queueid)
{
	uint32_t rc = ZXDH_OK;
	ZXDH_SPINLOCK_T *p_dtb_spinlock = NULL;
	ZXDH_DEV_SPINLOCK_TYPE_E spinlock = ZXDH_DEV_SPINLOCK_T_DTB;

	rc = zxdh_np_dev_opr_spinlock_get(devid, (uint32_t)spinlock, &p_dtb_spinlock);
	ZXDH_COMM_CHECK_DEV_RC(devid, rc, "zxdh_np_dev_opr_spinlock_get");

	zxdh_np_comm_spinlock_lock(p_dtb_spinlock);

	rc = zxdh_np_agent_channel_dtb_queue_release(devid, pname, queueid);

	if (rc == ZXDH_RC_DTB_QUEUE_NOT_ALLOC) {
		PMD_DRV_LOG(ERR, "dtb queue id %d not request.", queueid);
		zxdh_np_comm_spinlock_unlock(p_dtb_spinlock);
		return ZXDH_RC_DTB_QUEUE_NOT_ALLOC;
	}

	if (rc == ZXDH_RC_DTB_QUEUE_NAME_ERROR) {
		PMD_DRV_LOG(ERR, "dtb queue %d name error.", queueid);
		zxdh_np_comm_spinlock_unlock(p_dtb_spinlock);
		return ZXDH_RC_DTB_QUEUE_NAME_ERROR;
	}

	zxdh_np_comm_spinlock_unlock(p_dtb_spinlock);

	rc = zxdh_np_dtb_queue_id_free(devid, queueid);
	ZXDH_COMM_CHECK_DEV_RC(devid, rc, "zxdh_np_dtb_queue_id_free");

	PMD_DRV_LOG(INFO, "queueid %d", queueid);

	return rc;
}

static void
zxdh_np_dtb_mgr_destroy(uint32_t dev_id)
{
	if (p_dpp_dtb_mgr[dev_id] != NULL) {
		rte_free(p_dpp_dtb_mgr[dev_id]);
		p_dpp_dtb_mgr[dev_id] = NULL;
	}
}

static void
zxdh_np_sdt_mgr_destroy(uint32_t dev_id)
{
	ZXDH_SDT_SOFT_TABLE_T *p_sdt_tbl_temp = NULL;
	ZXDH_SDT_MGR_T *p_sdt_mgr = NULL;

	p_sdt_tbl_temp = ZXDH_SDT_SOFT_TBL_GET(dev_id);
	p_sdt_mgr = ZXDH_SDT_MGR_PTR_GET();

	if (p_sdt_tbl_temp != NULL)
		rte_free(p_sdt_tbl_temp);

	ZXDH_SDT_SOFT_TBL_GET(dev_id) = NULL;

	p_sdt_mgr->channel_num--;
}

static void
zxdh_np_dev_del(uint32_t dev_id)
{
	ZXDH_DEV_CFG_T *p_dev_info = NULL;
	ZXDH_DEV_MGR_T *p_dev_mgr  = NULL;

	p_dev_mgr = &g_dev_mgr;
	p_dev_info = p_dev_mgr->p_dev_array[dev_id];

	if (p_dev_info != NULL) {
		rte_free(p_dev_info);
		p_dev_mgr->p_dev_array[dev_id] = NULL;
		p_dev_mgr->device_num--;
	}
}

int
zxdh_np_online_uninit(uint32_t dev_id,
			char *port_name,
			uint32_t queue_id)
{
	uint32_t rc;

	rc = zxdh_np_dtb_queue_release(dev_id, port_name, queue_id);
	if (rc != 0)
		PMD_DRV_LOG(ERR, "dtb release port name %s queue id %d", port_name, queue_id);

	zxdh_np_dtb_mgr_destroy(dev_id);
	zxdh_np_sdt_mgr_destroy(dev_id);
	zxdh_np_dev_del(dev_id);

	return 0;
}

static uint32_t
zxdh_np_sdt_tbl_type_get(uint32_t dev_id, uint32_t sdt_no)
{
	return g_table_type[dev_id][sdt_no];
}


static ZXDH_DTB_TABLE_T *
zxdh_np_dtb_table_info_get(uint32_t table_type)
{
	return &g_dpp_dtb_table_info[table_type];
}

static uint32_t
zxdh_np_dtb_write_table_cmd(uint32_t dev_id,
			ZXDH_DTB_TABLE_INFO_E table_type,
			void *p_cmd_data,
			void *p_cmd_buff)
{
	uint32_t         field_cnt;
	ZXDH_DTB_TABLE_T     *p_table_info = NULL;
	ZXDH_DTB_FIELD_T     *p_field_info = NULL;
	uint32_t         temp_data;
	uint32_t         rc = 0;

	ZXDH_COMM_CHECK_POINT(p_cmd_data);
	ZXDH_COMM_CHECK_POINT(p_cmd_buff);
	p_table_info = zxdh_np_dtb_table_info_get(table_type);
	p_field_info = p_table_info->p_fields;
	ZXDH_COMM_CHECK_DEV_POINT(dev_id, p_table_info);

	for (field_cnt = 0; field_cnt < p_table_info->field_num; field_cnt++) {
		temp_data = *((uint32_t *)p_cmd_data + field_cnt) & ZXDH_COMM_GET_BIT_MASK(uint32_t,
			p_field_info[field_cnt].len);

		rc = zxdh_np_comm_write_bits_ex((uint8_t *)p_cmd_buff,
					ZXDH_DTB_TABLE_CMD_SIZE_BIT,
					temp_data,
					p_field_info[field_cnt].lsb_pos,
					p_field_info[field_cnt].len);

		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_np_comm_write_bits_ex");
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_smmu0_write_entry_data(uint32_t dev_id,
		uint32_t mode,
		uint32_t addr,
		uint32_t *p_data,
		ZXDH_DTB_ENTRY_T *p_entry)
{
	ZXDH_DTB_ERAM_TABLE_FORM_T dtb_eram_form_info = {0};
	uint32_t  rc = 0;

	dtb_eram_form_info.valid = ZXDH_DTB_TABLE_VALID;
	dtb_eram_form_info.type_mode = ZXDH_DTB_TABLE_MODE_ERAM;
	dtb_eram_form_info.data_mode = mode;
	dtb_eram_form_info.cpu_wr = 1;
	dtb_eram_form_info.addr = addr;
	dtb_eram_form_info.cpu_rd = 0;
	dtb_eram_form_info.cpu_rd_mode = 0;

	if (ZXDH_ERAM128_OPR_128b == mode) {
		p_entry->data_in_cmd_flag = 0;
		p_entry->data_size = 128 / 8;

		rc = zxdh_np_dtb_write_table_cmd(dev_id, ZXDH_DTB_TABLE_ERAM_128,
			&dtb_eram_form_info, p_entry->cmd);
		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_write_table_cmd");

		memcpy(p_entry->data, p_data, 128 / 8);
	} else if (ZXDH_ERAM128_OPR_64b == mode) {
		p_entry->data_in_cmd_flag = 1;
		p_entry->data_size  = 64 / 8;
		dtb_eram_form_info.data_l = *(p_data + 1);
		dtb_eram_form_info.data_h = *(p_data);

		rc = zxdh_np_dtb_write_table_cmd(dev_id, ZXDH_DTB_TABLE_ERAM_64,
			&dtb_eram_form_info, p_entry->cmd);
		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_write_table_cmd");

	} else if (ZXDH_ERAM128_OPR_1b == mode) {
		p_entry->data_in_cmd_flag = 1;
		p_entry->data_size  = 1;
		dtb_eram_form_info.data_h = *(p_data);

		rc = zxdh_np_dtb_write_table_cmd(dev_id, ZXDH_DTB_TABLE_ERAM_1,
			&dtb_eram_form_info, p_entry->cmd);
		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_write_table_cmd");
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_se_smmu0_ind_write(uint32_t dev_id,
		uint32_t base_addr,
		uint32_t index,
		uint32_t wrt_mode,
		uint32_t *p_data,
		ZXDH_DTB_ENTRY_T *p_entry)
{
	uint32_t temp_idx = 0;
	uint32_t dtb_ind_addr;
	uint32_t rc;

	switch (wrt_mode) {
	case ZXDH_ERAM128_OPR_128b:
		if ((0xFFFFFFFF - (base_addr)) < (index)) {
			PMD_DRV_LOG(ERR, "base addr:0x%x, index:0x%x invalid", base_addr, index);

			return ZXDH_PAR_CHK_INVALID_INDEX;
		}
		if (base_addr + index > ZXDH_SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
			PMD_DRV_LOG(ERR, "dpp_se_smmu0_ind_write : index out of range");
			return 1;
		}
		temp_idx = index << 7;
		break;
	case ZXDH_ERAM128_OPR_64b:
		if ((base_addr + (index >> 1)) > ZXDH_SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
			PMD_DRV_LOG(ERR, "dpp_se_smmu0_ind_write : index out of range");
			return 1;
		}
		temp_idx = index << 6;
		break;
	case ZXDH_ERAM128_OPR_1b:
		if ((base_addr + (index >> 7)) > ZXDH_SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
			PMD_DRV_LOG(ERR, "dpp_se_smmu0_ind_write : index out of range");
			return 1;
		}
		temp_idx = index;
		break;
	default:
		break;
	}

	dtb_ind_addr = ((base_addr << 7) & ZXDH_ERAM128_BADDR_MASK) + temp_idx;

	PMD_DRV_LOG(INFO, "dtb eram item 1bit addr: 0x%x", dtb_ind_addr);

	rc = zxdh_np_dtb_smmu0_write_entry_data(dev_id,
						  wrt_mode,
						  dtb_ind_addr,
						  p_data,
						  p_entry);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_smmu0_write_entry_data");

	return rc;
}

static uint32_t
zxdh_np_eram_dtb_len_get(uint32_t mode)
{
	uint32_t dtb_len = 0;

	switch (mode) {
	case ZXDH_ERAM128_OPR_128b:
		dtb_len += 2;
		break;
	case ZXDH_ERAM128_OPR_64b:
	case ZXDH_ERAM128_OPR_1b:
		dtb_len += 1;
		break;
	default:
		break;
	}

	return dtb_len;
}

static uint32_t
zxdh_np_dtb_eram_one_entry(uint32_t dev_id,
		uint32_t sdt_no,
		uint32_t del_en,
		void *pdata,
		uint32_t *p_dtb_len,
		ZXDH_DTB_ENTRY_T *p_dtb_one_entry)
{
	uint32_t buff[ZXDH_SMMU0_READ_REG_MAX_NUM]      = {0};
	ZXDH_SDT_TBL_ERAM_T sdt_eram           = {0};
	ZXDH_DTB_ERAM_ENTRY_INFO_T *peramdata = NULL;
	uint32_t base_addr;
	uint32_t index;
	uint32_t opr_mode;
	uint32_t rc = ZXDH_OK;

	ZXDH_COMM_CHECK_POINT(pdata);
	ZXDH_COMM_CHECK_POINT(p_dtb_one_entry);
	ZXDH_COMM_CHECK_POINT(p_dtb_len);

	peramdata = (ZXDH_DTB_ERAM_ENTRY_INFO_T *)pdata;
	index = peramdata->index;
	base_addr = sdt_eram.eram_base_addr;
	opr_mode = sdt_eram.eram_mode;

	switch (opr_mode) {
	case ZXDH_ERAM128_TBL_128b:
		opr_mode = ZXDH_ERAM128_OPR_128b;
		break;
	case ZXDH_ERAM128_TBL_64b:
		opr_mode = ZXDH_ERAM128_OPR_64b;
		break;
	case ZXDH_ERAM128_TBL_1b:
		opr_mode = ZXDH_ERAM128_OPR_1b;
		break;
	default:
		break;
	}

	if (del_en) {
		memset((uint8_t *)buff, 0, sizeof(buff));
		rc = zxdh_np_dtb_se_smmu0_ind_write(dev_id,
						base_addr,
						index,
						opr_mode,
						buff,
						p_dtb_one_entry);
		ZXDH_COMM_CHECK_DEV_RC(sdt_no, rc, "zxdh_dtb_se_smmu0_ind_write");
	} else {
		rc = zxdh_np_dtb_se_smmu0_ind_write(dev_id,
								   base_addr,
								   index,
								   opr_mode,
								   peramdata->p_data,
								   p_dtb_one_entry);
		ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_dtb_se_smmu0_ind_write");
	}
	*p_dtb_len = zxdh_np_eram_dtb_len_get(opr_mode);

	return rc;
}

static uint32_t
zxdh_np_dtb_data_write(uint8_t *p_data_buff,
			uint32_t addr_offset,
			ZXDH_DTB_ENTRY_T *entry)
{
	ZXDH_COMM_CHECK_POINT(p_data_buff);
	ZXDH_COMM_CHECK_POINT(entry);

	uint8_t *p_cmd = p_data_buff + addr_offset;
	uint32_t cmd_size = ZXDH_DTB_TABLE_CMD_SIZE_BIT / 8;

	uint8_t *p_data = p_cmd + cmd_size;
	uint32_t data_size = entry->data_size;

	uint8_t *cmd = (uint8_t *)entry->cmd;
	uint8_t *data = (uint8_t *)entry->data;

	memcpy(p_cmd, cmd, cmd_size);

	if (!entry->data_in_cmd_flag) {
		zxdh_np_comm_swap(data, data_size);
		memcpy(p_data, data, data_size);
	}

	return 0;
}

static uint32_t
zxdh_np_dtb_queue_enable_get(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t *enable)
{
	uint32_t rc = 0;
	ZXDH_DTB_QUEUE_VM_INFO_T vm_info = {0};

	rc = zxdh_np_dtb_queue_vm_info_get(dev_id, queue_id, &vm_info);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_dtb_queue_vm_info_get");

	*enable = vm_info.queue_en;
	return rc;
}

static uint32_t
zxdh_np_dtb_item_buff_wr(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t dir_flag,
		uint32_t index,
		uint32_t pos,
		uint32_t len,
		uint32_t *p_data)
{
	uint64_t addr;

	if (dir_flag == 1)
		addr = ZXDH_DTB_TAB_UP_VIR_ADDR_GET(dev_id, queue_id, index) +
			ZXDH_DTB_ITEM_ACK_SIZE + pos * 4;
	else
		addr = ZXDH_DTB_TAB_DOWN_VIR_ADDR_GET(dev_id, queue_id, index) +
			ZXDH_DTB_ITEM_ACK_SIZE + pos * 4;

	memcpy((uint8_t *)(addr), p_data, len * 4);

	return 0;
}

static uint32_t
zxdh_np_dtb_item_ack_rd(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t dir_flag,
		uint32_t index,
		uint32_t pos,
		uint32_t *p_data)
{
	uint64_t addr;
	uint32_t val;

	if (dir_flag == 1)
		addr = ZXDH_DTB_TAB_UP_VIR_ADDR_GET(dev_id, queue_id, index) + pos * 4;
	else
		addr = ZXDH_DTB_TAB_DOWN_VIR_ADDR_GET(dev_id, queue_id, index) + pos * 4;

	val = *((volatile uint32_t *)(addr));

	*p_data = val;

	return 0;
}

static uint32_t
zxdh_np_dtb_item_ack_wr(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t dir_flag,
		uint32_t index,
		uint32_t pos,
		uint32_t data)
{
	uint64_t addr;

	if (dir_flag == 1)
		addr = ZXDH_DTB_TAB_UP_VIR_ADDR_GET(dev_id, queue_id, index) + pos * 4;
	else
		addr = ZXDH_DTB_TAB_DOWN_VIR_ADDR_GET(dev_id, queue_id, index) + pos * 4;

	*((volatile uint32_t *)(addr)) = data;

	return 0;
}

static uint32_t
zxdh_np_dtb_queue_item_info_set(uint32_t dev_id,
		uint32_t queue_id,
		ZXDH_DTB_QUEUE_ITEM_INFO_T *p_item_info)
{
	uint32_t rc;

	uint32_t dtb_addr_h_reg = ZXDH_SYS_DTB_BASE_ADDR +
		ZXDH_MODULE_DTB_ENQ_BASE_ADDR + 0x0000;
	uint32_t dtb_addr_l_reg = ZXDH_SYS_DTB_BASE_ADDR +
		ZXDH_MODULE_DTB_ENQ_BASE_ADDR + 0x0004;
	uint32_t dtb_len_reg = ZXDH_SYS_DTB_BASE_ADDR +
		ZXDH_MODULE_DTB_ENQ_BASE_ADDR + 0x0008;
	uint32_t dtb_len = 0;

	rc = zxdh_np_dev_write_channel(dev_id, dtb_addr_h_reg + queue_id * 32,
		1, &p_item_info->data_hddr);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dev_write_channel Fail");
	rc = zxdh_np_dev_write_channel(dev_id, dtb_addr_l_reg + queue_id * 32,
		1, &p_item_info->data_laddr);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dev_write_channel Fail");
	dtb_len = ZXDH_DTB_LEN(p_item_info->cmd_type, p_item_info->int_en, p_item_info->data_len);
	rc = zxdh_np_dev_write_channel(dev_id, dtb_len_reg + queue_id * 32, 1, &dtb_len);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dev_write_channel Fail");
	return rc;
}

static uint32_t
zxdh_np_dtb_tab_down_info_set(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t int_flag,
		uint32_t data_len,
		uint32_t *p_data,
		uint32_t *p_item_index)
{
	ZXDH_DTB_QUEUE_ITEM_INFO_T item_info = {0};
	uint32_t unused_item_num = 0;
	uint32_t queue_en = 0;
	uint32_t ack_vale = 0;
	uint64_t phy_addr;
	uint32_t item_index;
	uint32_t i;
	uint32_t rc;
	ZXDH_SPINLOCK_T *p_spinlock = NULL;

	zxdh_np_dev_dtb_opr_spinlock_get(dev_id, ZXDH_DEV_SPINLOCK_T_DTB, queue_id, &p_spinlock);
	zxdh_np_comm_spinlock_lock(p_spinlock);

	if (ZXDH_DTB_QUEUE_INIT_FLAG_GET(dev_id, queue_id) == 0) {
		PMD_DRV_LOG(ERR, "dtb queue %d is not init.", queue_id);
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (data_len % 4 != 0) {
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_PARA_INVALID;
	}

	rc = zxdh_np_dtb_queue_enable_get(dev_id, queue_id, &queue_en);
	if (!queue_en) {
		PMD_DRV_LOG(ERR, "the queue %d is not enable!,rc=%d", queue_id, rc);
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_NOT_ENABLE;
	}

	rc = zxdh_np_dtb_queue_unused_item_num_get(dev_id, queue_id, &unused_item_num);
	if (unused_item_num == 0) {
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_ITEM_HW_EMPTY;
	}

	for (i = 0; i < ZXDH_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		item_index = ZXDH_DTB_TAB_DOWN_WR_INDEX_GET(dev_id, queue_id) %
			ZXDH_DTB_QUEUE_ITEM_NUM_MAX;

		rc = zxdh_np_dtb_item_ack_rd(dev_id, queue_id, 0,
			item_index, 0, &ack_vale);

		ZXDH_DTB_TAB_DOWN_WR_INDEX_GET(dev_id, queue_id)++;

		if ((ack_vale >> 8) == ZXDH_DTB_TAB_ACK_UNUSED_MASK)
			break;
	}

	if (i == ZXDH_DTB_QUEUE_ITEM_NUM_MAX) {
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_ITEM_SW_EMPTY;
	}

	rc = zxdh_np_dtb_item_buff_wr(dev_id, queue_id, 0,
		item_index, 0, data_len, p_data);

	rc = zxdh_np_dtb_item_ack_wr(dev_id, queue_id, 0,
		item_index, 0, ZXDH_DTB_TAB_ACK_IS_USING_MASK);

	item_info.cmd_vld = 1;
	item_info.cmd_type = 0;
	item_info.int_en = int_flag;
	item_info.data_len = data_len / 4;
	phy_addr = p_dpp_dtb_mgr[dev_id]->queue_info[queue_id].tab_down.start_phy_addr +
		item_index * p_dpp_dtb_mgr[dev_id]->queue_info[queue_id].tab_down.item_size;
	item_info.data_hddr = ((phy_addr >> 4) >> 32) & 0xffffffff;
	item_info.data_laddr = (phy_addr >> 4) & 0xffffffff;

	rc = zxdh_np_dtb_queue_item_info_set(dev_id, queue_id, &item_info);
	*p_item_index = item_index;

	zxdh_np_comm_spinlock_unlock(p_spinlock);

	return rc;
}

static uint32_t
zxdh_np_dtb_write_down_table_data(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t down_table_len,
		uint8_t *p_down_table_buff,
		uint32_t *p_element_id)
{
	uint32_t  rc = 0;
	uint32_t dtb_interrupt_status = 0;

	rc = zxdh_np_dtb_tab_down_info_set(dev_id,
					queue_id,
					dtb_interrupt_status,
					down_table_len / 4,
					(uint32_t *)p_down_table_buff,
					p_element_id);
	return rc;
}

int
zxdh_np_dtb_table_entry_write(uint32_t dev_id,
			uint32_t queue_id,
			uint32_t entrynum,
			ZXDH_DTB_USER_ENTRY_T *down_entries)
{
	ZXDH_DTB_USER_ENTRY_T *pentry = NULL;
	ZXDH_DTB_ENTRY_T   dtb_one_entry = {0};
	uint8_t entry_cmd[ZXDH_DTB_TABLE_CMD_SIZE_BIT] = {0};
	uint8_t entry_data[ZXDH_ETCAM_WIDTH_MAX] = {0};
	uint8_t *p_data_buff = NULL;
	uint32_t element_id = 0xff;
	uint32_t one_dtb_len = 0;
	uint32_t dtb_len = 0;
	uint32_t entry_index;
	uint32_t sdt_no;
	uint32_t tbl_type;
	uint32_t addr_offset;
	uint32_t max_size;
	uint32_t rc;

	p_data_buff = rte_zmalloc(NULL, ZXDH_DTB_TABLE_DATA_BUFF_SIZE, 0);
	ZXDH_COMM_CHECK_POINT(p_data_buff);

	dtb_one_entry.cmd = entry_cmd;
	dtb_one_entry.data = entry_data;

	max_size = (ZXDH_DTB_TABLE_DATA_BUFF_SIZE / 16) - 1;

	for (entry_index = 0; entry_index < entrynum; entry_index++) {
		pentry = down_entries + entry_index;
		sdt_no = pentry->sdt_no;
		tbl_type = zxdh_np_sdt_tbl_type_get(dev_id, sdt_no);
		switch (tbl_type) {
		case ZXDH_SDT_TBLT_ERAM:
			rc = zxdh_np_dtb_eram_one_entry(dev_id, sdt_no, ZXDH_DTB_ITEM_ADD_OR_UPDATE,
				pentry->p_entry_data, &one_dtb_len, &dtb_one_entry);
			break;
		default:
			PMD_DRV_LOG(ERR, "SDT table_type[ %d ] is invalid!", tbl_type);
			rte_free(p_data_buff);
			return 1;
		}

		addr_offset = dtb_len * ZXDH_DTB_LEN_POS_SETP;
		dtb_len += one_dtb_len;
		if (dtb_len > max_size) {
			rte_free(p_data_buff);
			PMD_DRV_LOG(ERR, "error dtb_len>%u!", max_size);
			return ZXDH_RC_DTB_DOWN_LEN_INVALID;
		}
		rc = zxdh_np_dtb_data_write(p_data_buff, addr_offset, &dtb_one_entry);
		memset(entry_cmd, 0x0, sizeof(entry_cmd));
		memset(entry_data, 0x0, sizeof(entry_data));
	}

	if (dtb_len == 0) {
		rte_free(p_data_buff);
		return ZXDH_RC_DTB_DOWN_LEN_INVALID;
	}

	rc = zxdh_np_dtb_write_down_table_data(dev_id,
					queue_id,
					dtb_len * 16,
					p_data_buff,
					&element_id);
	rte_free(p_data_buff);


	return rc;
}

static void
zxdh_np_sdt_tbl_data_get(uint32_t dev_id, uint32_t sdt_no, ZXDH_SDT_TBL_DATA_T *p_sdt_data)
{
	p_sdt_data->data_high32 = g_sdt_info[dev_id][sdt_no].data_high32;
	p_sdt_data->data_low32  = g_sdt_info[dev_id][sdt_no].data_low32;
}

int
zxdh_np_dtb_table_entry_delete(uint32_t dev_id,
			 uint32_t queue_id,
			 uint32_t entrynum,
			 ZXDH_DTB_USER_ENTRY_T *delete_entries)
{
	ZXDH_SDT_TBL_DATA_T sdt_tbl = {0};
	ZXDH_DTB_USER_ENTRY_T *pentry = NULL;
	ZXDH_DTB_ENTRY_T   dtb_one_entry = {0};
	uint8_t entry_cmd[ZXDH_DTB_TABLE_CMD_SIZE_BIT / 8] = {0};
	uint8_t entry_data[ZXDH_ETCAM_WIDTH_MAX / 8] = {0};
	uint8_t *p_data_buff = NULL;
	uint32_t tbl_type = 0;
	uint32_t element_id = 0xff;
	uint32_t one_dtb_len = 0;
	uint32_t dtb_len = 0;
	uint32_t entry_index;
	uint32_t sdt_no;
	uint32_t addr_offset;
	uint32_t max_size;
	uint32_t rc;

	ZXDH_COMM_CHECK_POINT(delete_entries);

	p_data_buff = rte_calloc(NULL, 1, ZXDH_DTB_TABLE_DATA_BUFF_SIZE, 0);
	ZXDH_COMM_CHECK_POINT(p_data_buff);

	dtb_one_entry.cmd = entry_cmd;
	dtb_one_entry.data = entry_data;

	max_size = (ZXDH_DTB_TABLE_DATA_BUFF_SIZE / 16) - 1;

	for (entry_index = 0; entry_index < entrynum; entry_index++) {
		pentry = delete_entries + entry_index;

		sdt_no = pentry->sdt_no;
		zxdh_np_sdt_tbl_data_get(dev_id, sdt_no, &sdt_tbl);
		switch (tbl_type) {
		case ZXDH_SDT_TBLT_ERAM:
			rc = zxdh_np_dtb_eram_one_entry(dev_id, sdt_no, ZXDH_DTB_ITEM_DELETE,
				pentry->p_entry_data, &one_dtb_len, &dtb_one_entry);
			break;
		default:
			PMD_DRV_LOG(ERR, "SDT table_type[ %d ] is invalid!", tbl_type);
			rte_free(p_data_buff);
			return 1;
		}

		addr_offset = dtb_len * ZXDH_DTB_LEN_POS_SETP;
		dtb_len += one_dtb_len;
		if (dtb_len > max_size) {
			rte_free(p_data_buff);
			PMD_DRV_LOG(ERR, "error dtb_len>%u!", max_size);
			return ZXDH_RC_DTB_DOWN_LEN_INVALID;
		}

		rc = zxdh_np_dtb_data_write(p_data_buff, addr_offset, &dtb_one_entry);
		memset(entry_cmd, 0x0, sizeof(entry_cmd));
		memset(entry_data, 0x0, sizeof(entry_data));
	}

	if (dtb_len == 0) {
		rte_free(p_data_buff);
		return ZXDH_RC_DTB_DOWN_LEN_INVALID;
	}

	rc = zxdh_np_dtb_write_down_table_data(dev_id,
				queue_id,
				dtb_len * 16,
				p_data_buff,
				&element_id);
	rte_free(p_data_buff);

	return rc;
}

static uint32_t
zxdh_np_sdt_tbl_data_parser(uint32_t sdt_hig32, uint32_t sdt_low32, void *p_sdt_info)
{
	uint32_t tbl_type = 0;
	uint32_t clutch_en = 0;

	ZXDH_SDT_TBL_ERAM_T *p_sdt_eram = NULL;
	ZXDH_SDT_TBL_PORT_TBL_T *p_sdt_porttbl = NULL;

	ZXDH_COMM_UINT32_GET_BITS(tbl_type, sdt_hig32,
		ZXDH_SDT_H_TBL_TYPE_BT_POS, ZXDH_SDT_H_TBL_TYPE_BT_LEN);
	ZXDH_COMM_UINT32_GET_BITS(clutch_en, sdt_low32, 0, 1);

	switch (tbl_type) {
	case ZXDH_SDT_TBLT_ERAM:
		p_sdt_eram = (ZXDH_SDT_TBL_ERAM_T *)p_sdt_info;
		p_sdt_eram->table_type = tbl_type;
		p_sdt_eram->eram_clutch_en = clutch_en;
		break;

	case ZXDH_SDT_TBLT_PORTTBL:
		p_sdt_porttbl = (ZXDH_SDT_TBL_PORT_TBL_T *)p_sdt_info;
		p_sdt_porttbl->table_type = tbl_type;
		p_sdt_porttbl->porttbl_clutch_en = clutch_en;
		break;
	default:
		PMD_DRV_LOG(ERR, "SDT table_type[ %d ] is invalid!", tbl_type);
		return 1;
	}

	return 0;
}

static uint32_t
zxdh_np_soft_sdt_tbl_get(uint32_t dev_id, uint32_t sdt_no, void *p_sdt_info)
{
	ZXDH_SDT_TBL_DATA_T sdt_tbl = {0};
	uint32_t rc;

	zxdh_np_sdt_tbl_data_get(dev_id, sdt_no, &sdt_tbl);

	rc = zxdh_np_sdt_tbl_data_parser(sdt_tbl.data_high32, sdt_tbl.data_low32, p_sdt_info);
	if (rc != 0)
		PMD_DRV_LOG(ERR, "dpp sdt [%d] tbl_data_parser error", sdt_no);

	return rc;
}

static void
zxdh_np_eram_index_cal(uint32_t eram_mode, uint32_t index,
		uint32_t *p_row_index, uint32_t *p_col_index)
{
	uint32_t row_index = 0;
	uint32_t col_index = 0;

	switch (eram_mode) {
	case ZXDH_ERAM128_TBL_128b:
		row_index = index;
		break;
	case ZXDH_ERAM128_TBL_64b:
		row_index = (index >> 1);
		col_index = index & 0x1;
		break;
	case ZXDH_ERAM128_TBL_1b:
		row_index = (index >> 7);
		col_index = index & 0x7F;
		break;
	default:
		break;
	}
	*p_row_index = row_index;
	*p_col_index = col_index;
}

static uint32_t
zxdh_np_dtb_eram_data_get(uint32_t dev_id, uint32_t queue_id, uint32_t sdt_no,
		ZXDH_DTB_ERAM_ENTRY_INFO_T *p_dump_eram_entry)
{
	uint32_t index = p_dump_eram_entry->index;
	uint32_t *p_data = p_dump_eram_entry->p_data;
	ZXDH_SDT_TBL_ERAM_T sdt_eram_info = {0};
	uint32_t temp_data[4] = {0};
	uint32_t row_index = 0;
	uint32_t col_index = 0;
	uint32_t rd_mode;
	uint32_t rc;

	rc = zxdh_np_soft_sdt_tbl_get(queue_id, sdt_no, &sdt_eram_info);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_soft_sdt_tbl_get");
	rd_mode = sdt_eram_info.eram_mode;

	zxdh_np_eram_index_cal(rd_mode, index, &row_index, &col_index);

	switch (rd_mode) {
	case ZXDH_ERAM128_TBL_128b:
		memcpy(p_data, temp_data, (128 / 8));
		break;
	case ZXDH_ERAM128_TBL_64b:
		memcpy(p_data, temp_data + ((1 - col_index) << 1), (64 / 8));
		break;
	case ZXDH_ERAM128_TBL_1b:
		ZXDH_COMM_UINT32_GET_BITS(p_data[0], *(temp_data +
			(3 - col_index / 32)), (col_index % 32), 1);
		break;
	default:
		break;
	}
	return rc;
}

int
zxdh_np_dtb_table_entry_get(uint32_t dev_id,
		 uint32_t queue_id,
		 ZXDH_DTB_USER_ENTRY_T *get_entry,
		 uint32_t srh_mode)
{
	ZXDH_SDT_TBL_DATA_T sdt_tbl = {0};
	uint32_t tbl_type = 0;
	uint32_t rc;
	uint32_t sdt_no;

	sdt_no = get_entry->sdt_no;
	zxdh_np_sdt_tbl_data_get(srh_mode, sdt_no, &sdt_tbl);

	ZXDH_COMM_UINT32_GET_BITS(tbl_type, sdt_tbl.data_high32,
			ZXDH_SDT_H_TBL_TYPE_BT_POS, ZXDH_SDT_H_TBL_TYPE_BT_LEN);
	switch (tbl_type) {
	case ZXDH_SDT_TBLT_ERAM:
		rc = zxdh_np_dtb_eram_data_get(dev_id,
				queue_id,
				sdt_no,
				(ZXDH_DTB_ERAM_ENTRY_INFO_T *)get_entry->p_entry_data);
		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_eram_data_get");
		break;
	default:
		PMD_DRV_LOG(ERR, "SDT table_type[ %d ] is invalid!", tbl_type);
		return 1;
	}

	return 0;
}

static void
zxdh_np_stat_cfg_soft_get(uint32_t dev_id,
				ZXDH_PPU_STAT_CFG_T *p_stat_cfg)
{
	ZXDH_COMM_CHECK_DEV_POINT(dev_id, p_stat_cfg);

	p_stat_cfg->ddr_base_addr = g_ppu_stat_cfg[dev_id].ddr_base_addr;
	p_stat_cfg->eram_baddr = g_ppu_stat_cfg[dev_id].eram_baddr;
	p_stat_cfg->eram_depth = g_ppu_stat_cfg[dev_id].eram_depth;
	p_stat_cfg->ppu_addr_offset = g_ppu_stat_cfg[dev_id].ppu_addr_offset;
}

static uint32_t
zxdh_np_dtb_tab_up_info_set(uint32_t dev_id,
			uint32_t queue_id,
			uint32_t item_index,
			uint32_t int_flag,
			uint32_t data_len,
			uint32_t desc_len,
			uint32_t *p_desc_data)
{
	ZXDH_DTB_QUEUE_ITEM_INFO_T item_info = {0};
	uint32_t queue_en = 0;
	uint32_t rc;
	ZXDH_SPINLOCK_T *p_spinlock = NULL;

	zxdh_np_dev_dtb_opr_spinlock_get(dev_id, ZXDH_DEV_SPINLOCK_T_DTB, queue_id, &p_spinlock);
	zxdh_np_comm_spinlock_lock(p_spinlock);

	zxdh_np_dtb_queue_enable_get(dev_id, queue_id, &queue_en);
	if (!queue_en) {
		PMD_DRV_LOG(ERR, "the queue %d is not enable!", queue_id);
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_NOT_ENABLE;
	}

	if (ZXDH_DTB_QUEUE_INIT_FLAG_GET(dev_id, queue_id) == 0) {
		PMD_DRV_LOG(ERR, "dtb queue %d is not init", queue_id);
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (desc_len % 4 != 0) {
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_PARA_INVALID;
	}

	zxdh_np_dtb_item_buff_wr(dev_id, queue_id, ZXDH_DTB_DIR_UP_TYPE,
		item_index, 0, desc_len, p_desc_data);

	ZXDH_DTB_TAB_UP_DATA_LEN_GET(dev_id, queue_id, item_index) = data_len;

	item_info.cmd_vld = 1;
	item_info.cmd_type = ZXDH_DTB_DIR_UP_TYPE;
	item_info.int_en = int_flag;
	item_info.data_len = desc_len / 4;

	rc = zxdh_np_dtb_queue_item_info_set(dev_id, queue_id, &item_info);

	zxdh_np_comm_spinlock_unlock(p_spinlock);

	return rc;
}

static uint32_t
zxdh_np_dtb_write_dump_desc_info(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t queue_element_id,
		uint32_t *p_dump_info,
		uint32_t data_len,
		uint32_t desc_len,
		uint32_t *p_dump_data)
{
	uint32_t dtb_interrupt_status = 0;
	uint32_t rc;

	ZXDH_COMM_CHECK_POINT(p_dump_data);
	rc = zxdh_np_dtb_tab_up_info_set(dev_id,
				queue_id,
				queue_element_id,
				dtb_interrupt_status,
				data_len,
				desc_len,
				p_dump_info);
	if (rc != 0) {
		PMD_DRV_LOG(ERR, "the queue %d element id %d dump"
			" info set failed!", queue_id, queue_element_id);
		zxdh_np_dtb_item_ack_wr(dev_id, queue_id, ZXDH_DTB_DIR_UP_TYPE,
			queue_element_id, 0, ZXDH_DTB_TAB_ACK_UNUSED_MASK);
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_tab_up_free_item_get(uint32_t dev_id,
					uint32_t queue_id,
					uint32_t *p_item_index)
{
	uint32_t ack_vale = 0;
	uint32_t item_index = 0;
	uint32_t unused_item_num = 0;
	uint32_t i;
	ZXDH_SPINLOCK_T *p_spinlock = NULL;

	zxdh_np_dev_dtb_opr_spinlock_get(dev_id, ZXDH_DEV_SPINLOCK_T_DTB, queue_id, &p_spinlock);
	zxdh_np_comm_spinlock_lock(p_spinlock);

	if (ZXDH_DTB_QUEUE_INIT_FLAG_GET(dev_id, queue_id) == 0) {
		PMD_DRV_LOG(ERR, "dtb queue %d is not init", queue_id);
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	zxdh_np_dtb_queue_unused_item_num_get(dev_id, queue_id, &unused_item_num);

	if (unused_item_num == 0) {
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_ITEM_HW_EMPTY;
	}

	for (i = 0; i < ZXDH_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		item_index = ZXDH_DTB_TAB_UP_WR_INDEX_GET(dev_id, queue_id) %
			ZXDH_DTB_QUEUE_ITEM_NUM_MAX;

		zxdh_np_dtb_item_ack_rd(dev_id, queue_id, ZXDH_DTB_DIR_UP_TYPE, item_index,
			0, &ack_vale);

		ZXDH_DTB_TAB_UP_WR_INDEX_GET(dev_id, queue_id)++;

		if ((ack_vale >> 8) == ZXDH_DTB_TAB_ACK_UNUSED_MASK)
			break;
	}

	if (i == ZXDH_DTB_QUEUE_ITEM_NUM_MAX) {
		zxdh_np_comm_spinlock_unlock(p_spinlock);
		return ZXDH_RC_DTB_QUEUE_ITEM_SW_EMPTY;
	}

	zxdh_np_dtb_item_ack_wr(dev_id, queue_id, ZXDH_DTB_DIR_UP_TYPE, item_index,
		0, ZXDH_DTB_TAB_ACK_IS_USING_MASK);

	*p_item_index = item_index;

	zxdh_np_comm_spinlock_unlock(p_spinlock);

	return 0;
}

static uint32_t
zxdh_np_dtb_tab_up_item_addr_get(uint32_t dev_id,
					uint32_t queue_id,
					uint32_t item_index,
					uint32_t *p_phy_haddr,
					uint32_t *p_phy_laddr)
{
	uint32_t rc = 0;
	uint64_t addr;

	if (ZXDH_DTB_QUEUE_INIT_FLAG_GET(dev_id, queue_id) == 0) {
		PMD_DRV_LOG(ERR, "dtb queue %d is not init", queue_id);
		return ZXDH_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (ZXDH_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(dev_id, queue_id, item_index) ==
		ZXDH_DTB_TAB_UP_USER_ADDR_TYPE)
		addr = ZXDH_DTB_TAB_UP_USER_PHY_ADDR_GET(dev_id, queue_id, item_index);
	else
		addr = ZXDH_DTB_ITEM_ACK_SIZE;

	*p_phy_haddr = (addr >> 32) & 0xffffffff;
	*p_phy_laddr = addr & 0xffffffff;

	return rc;
}

static uint32_t
zxdh_np_dtb_se_smmu0_dma_dump(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t base_addr,
		uint32_t depth,
		uint32_t *p_data,
		uint32_t *element_id)
{
	uint8_t form_buff[ZXDH_DTB_TABLE_CMD_SIZE_BIT / 8] = {0};
	uint32_t dump_dst_phy_haddr = 0;
	uint32_t dump_dst_phy_laddr = 0;
	uint32_t queue_item_index = 0;
	uint32_t data_len;
	uint32_t desc_len;
	uint32_t rc;

	rc = zxdh_np_dtb_tab_up_free_item_get(dev_id, queue_id, &queue_item_index);
	if (rc != 0) {
		PMD_DRV_LOG(ERR, "dpp_dtb_tab_up_free_item_get failed = %d!", base_addr);
		return ZXDH_RC_DTB_QUEUE_ITEM_SW_EMPTY;
	}

	*element_id = queue_item_index;

	rc = zxdh_np_dtb_tab_up_item_addr_get(dev_id, queue_id, queue_item_index,
		&dump_dst_phy_haddr, &dump_dst_phy_laddr);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_tab_up_item_addr_get");

	data_len = depth * 128 / 32;
	desc_len = ZXDH_DTB_LEN_POS_SETP / 4;

	rc = zxdh_np_dtb_write_dump_desc_info(dev_id, queue_id, queue_item_index,
		(uint32_t *)form_buff, data_len, desc_len, p_data);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_write_dump_desc_info");

	return rc;
}

static uint32_t
zxdh_np_dtb_se_smmu0_ind_read(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t base_addr,
		uint32_t index,
		uint32_t rd_mode,
		uint32_t *p_data)
{
	uint32_t temp_data[4] = {0};
	uint32_t element_id = 0;
	uint32_t row_index = 0;
	uint32_t col_index = 0;
	uint32_t eram_dump_base_addr;
	uint32_t rc;

	switch (rd_mode) {
	case ZXDH_ERAM128_OPR_128b:
		row_index = index;
		break;
	case ZXDH_ERAM128_OPR_64b:
		row_index = (index >> 1);
		col_index = index & 0x1;
		break;
	case ZXDH_ERAM128_OPR_1b:
		row_index = (index >> 7);
		col_index = index & 0x7F;
		break;
	default:
		break;
	}

	eram_dump_base_addr = base_addr + row_index;
	rc = zxdh_np_dtb_se_smmu0_dma_dump(dev_id,
			queue_id,
			eram_dump_base_addr,
			1,
			temp_data,
			&element_id);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_np_dtb_se_smmu0_dma_dump");

	switch (rd_mode) {
	case ZXDH_ERAM128_OPR_128b:
		memcpy(p_data, temp_data, (128 / 8));
		break;
	case ZXDH_ERAM128_OPR_64b:
		memcpy(p_data, temp_data + ((1 - col_index) << 1), (64 / 8));
		break;
	case ZXDH_ERAM128_OPR_1b:
		ZXDH_COMM_UINT32_GET_BITS(p_data[0], *(temp_data +
			(3 - col_index / 32)), (col_index % 32), 1);
		break;
	default:
		break;
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_stat_smmu0_int_read(uint32_t dev_id,
		uint32_t queue_id,
		uint32_t smmu0_base_addr,
		ZXDH_STAT_CNT_MODE_E rd_mode,
		uint32_t index,
		uint32_t *p_data)
{
	uint32_t eram_rd_mode;
	uint32_t rc;

	ZXDH_COMM_CHECK_DEV_POINT(dev_id, p_data);

	if (rd_mode == ZXDH_STAT_128_MODE)
		eram_rd_mode = ZXDH_ERAM128_OPR_128b;
	else
		eram_rd_mode = ZXDH_ERAM128_OPR_64b;

	rc = zxdh_np_dtb_se_smmu0_ind_read(dev_id,
								   queue_id,
								   smmu0_base_addr,
								   index,
								   eram_rd_mode,
								   p_data);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_np_dtb_se_smmu0_ind_read");

	return rc;
}

int
zxdh_np_dtb_stats_get(uint32_t dev_id,
		uint32_t queue_id,
		ZXDH_STAT_CNT_MODE_E rd_mode,
		uint32_t index,
		uint32_t *p_data)
{
	ZXDH_PPU_STAT_CFG_T stat_cfg = {0};
	uint32_t ppu_eram_baddr;
	uint32_t ppu_eram_depth;
	uint32_t rc = 0;

	ZXDH_COMM_CHECK_DEV_POINT(dev_id, p_data);

	memset(&stat_cfg, 0x0, sizeof(stat_cfg));

	zxdh_np_stat_cfg_soft_get(dev_id, &stat_cfg);

	ppu_eram_depth = stat_cfg.eram_depth;
	ppu_eram_baddr = stat_cfg.eram_baddr;

	if ((index >> (ZXDH_STAT_128_MODE - rd_mode)) < ppu_eram_depth) {
		rc = zxdh_np_dtb_stat_smmu0_int_read(dev_id,
									queue_id,
									ppu_eram_baddr,
									rd_mode,
									index,
									p_data);
		ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_stat_smmu0_int_read");
	}

	return rc;
}

static uint32_t
zxdh_np_dtb_queue_down_init(uint32_t dev_id,
							uint32_t queue_id,
							ZXDH_DTB_QUEUE_CFG_T *p_queue_cfg)
{
	uint32_t rc = 0;
	uint32_t i = 0;
	uint32_t ack_vale = 0;
	uint32_t tab_down_item_size = 0;
	ZXDH_DTB_MGR_T *p_dtb_mgr = NULL;

	p_dtb_mgr = zxdh_np_dtb_mgr_get(dev_id);
	p_dtb_mgr->queue_info[queue_id].init_flag = 1;

	tab_down_item_size = (p_queue_cfg->down_item_size == 0) ?
		ZXDH_DTB_ITEM_SIZE : p_queue_cfg->down_item_size;

	p_dtb_mgr->queue_info[queue_id].tab_down.item_size = tab_down_item_size;
	p_dtb_mgr->queue_info[queue_id].tab_down.start_phy_addr = p_queue_cfg->down_start_phy_addr;
	p_dtb_mgr->queue_info[queue_id].tab_down.start_vir_addr = p_queue_cfg->down_start_vir_addr;
	p_dtb_mgr->queue_info[queue_id].tab_down.wr_index = 0;
	p_dtb_mgr->queue_info[queue_id].tab_down.rd_index = 0;

	for (i = 0; i < ZXDH_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		rc = zxdh_np_dtb_item_ack_wr(dev_id, queue_id,
			ZXDH_DTB_DIR_DOWN_TYPE, i, 0, ZXDH_DTB_TAB_ACK_CHECK_VALUE);
		ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dtb_item_ack_wr");
	}

	for (i = 0; i < ZXDH_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		rc = zxdh_np_dtb_item_ack_rd(dev_id, queue_id,
			ZXDH_DTB_DIR_DOWN_TYPE, i, 0, &ack_vale);
		if (ack_vale != ZXDH_DTB_TAB_ACK_CHECK_VALUE) {
			PMD_DRV_LOG(ERR, "dtb queue [%d] down init failed!", queue_id);
			return ZXDH_RC_DTB_MEMORY_ALLOC_ERR;
		}
	}

	memset((uint8_t *)(p_queue_cfg->down_start_vir_addr), 0,
		tab_down_item_size * ZXDH_DTB_QUEUE_ITEM_NUM_MAX);

	PMD_DRV_LOG(INFO, "dtb queue [%d] down init success!!!", queue_id);

	return ZXDH_OK;
}

static uint32_t
zxdh_np_dtb_queue_dump_init(uint32_t dev_id,
					uint32_t queue_id,
					ZXDH_DTB_QUEUE_CFG_T *p_queue_cfg)
{
	uint32_t i = 0;
	uint32_t ack_vale = 0;
	uint32_t tab_up_item_size = 0;
	ZXDH_DTB_MGR_T *p_dtb_mgr = NULL;

	p_dtb_mgr = zxdh_np_dtb_mgr_get(dev_id);
	p_dtb_mgr->queue_info[queue_id].init_flag = 1;

	tab_up_item_size = (p_queue_cfg->up_item_size == 0) ?
		ZXDH_DTB_ITEM_SIZE : p_queue_cfg->up_item_size;

	p_dtb_mgr->queue_info[queue_id].tab_up.item_size = tab_up_item_size;
	p_dtb_mgr->queue_info[queue_id].tab_up.start_phy_addr = p_queue_cfg->up_start_phy_addr;
	p_dtb_mgr->queue_info[queue_id].tab_up.start_vir_addr = p_queue_cfg->up_start_vir_addr;
	p_dtb_mgr->queue_info[queue_id].tab_up.wr_index = 0;
	p_dtb_mgr->queue_info[queue_id].tab_up.rd_index = 0;

	for (i = 0; i < ZXDH_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		zxdh_np_dtb_item_ack_wr(dev_id, queue_id,
			ZXDH_DTB_DIR_UP_TYPE, i, 0, ZXDH_DTB_TAB_ACK_CHECK_VALUE);
	}

	for (i = 0; i < ZXDH_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		zxdh_np_dtb_item_ack_rd(dev_id, queue_id,
			ZXDH_DTB_DIR_UP_TYPE, i, 0, &ack_vale);
		if (ack_vale != ZXDH_DTB_TAB_ACK_CHECK_VALUE) {
			PMD_DRV_LOG(ERR, "dtb queue [%d] dump init failed!!!", queue_id);
			return ZXDH_RC_DTB_MEMORY_ALLOC_ERR;
		}
	}

	memset((uint8_t *)(p_queue_cfg->up_start_vir_addr), 0,
		tab_up_item_size * ZXDH_DTB_QUEUE_ITEM_NUM_MAX);

	PMD_DRV_LOG(INFO, "dtb queue [%d] up init success!!!", queue_id);

	return ZXDH_OK;
}

static void
zxdh_np_dtb_down_channel_addr_set(uint32_t dev_id,
								uint32_t channel_id,
								uint64_t phy_addr,
								uint64_t vir_addr,
								uint32_t size)
{
	ZXDH_DTB_QUEUE_CFG_T down_queue_cfg = {
		.down_start_phy_addr = phy_addr,
		.down_start_vir_addr = vir_addr,
		.down_item_size = size,
	};

	zxdh_np_dtb_queue_down_init(dev_id, channel_id, &down_queue_cfg);
}

static void
zxdh_np_dtb_dump_channel_addr_set(uint32_t dev_id,
								uint32_t channel_id,
								uint64_t phy_addr,
								uint64_t vir_addr,
								uint32_t size)
{
	ZXDH_DTB_QUEUE_CFG_T dump_queue_cfg = {
		.up_start_phy_addr = phy_addr,
		.up_start_vir_addr = vir_addr,
		.up_item_size = size,
	};

	zxdh_np_dtb_queue_dump_init(dev_id, channel_id, &dump_queue_cfg);
}

static uint32_t
zxdh_np_dtb_user_info_set(uint32_t dev_id, uint32_t queue_id, uint16_t vport, uint32_t vector)
{
	uint32_t rc = ZXDH_OK;

	ZXDH_DTB_QUEUE_VM_INFO_T vm_info = {0};
	ZXDH_DTB_MGR_T *p_dtb_mgr = zxdh_np_dtb_mgr_get(dev_id);

	rc = zxdh_np_dtb_queue_vm_info_get(dev_id, queue_id, &vm_info);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dtb_queue_vm_info_get");

	vm_info.dbi_en = 1;
	vm_info.epid = hardware_ep_id[ZXDH_EPID_BY(vport)];
	vm_info.vfunc_num = ZXDH_VFUNC_NUM(vport);
	vm_info.func_num = ZXDH_FUNC_NUM(vport);
	vm_info.vfunc_active = ZXDH_VF_ACTIVE(vport);
	vm_info.vector = vector;

	p_dtb_mgr->queue_info[queue_id].vport = vport;
	p_dtb_mgr->queue_info[queue_id].vector = vector;

	rc = zxdh_np_dtb_queue_vm_info_set(dev_id, queue_id, &vm_info);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dtb_queue_vm_info_set");

	return rc;
}

static uint32_t
zxdh_np_apt_dtb_res_init(uint32_t dev_id, ZXDH_DEV_INIT_CTRL_T *p_dev_init_ctrl)
{
	uint32_t rc = ZXDH_OK;

	uint32_t queue_id = 0;

	rc = zxdh_np_dtb_queue_request(dev_id, p_dev_init_ctrl->port_name,
		p_dev_init_ctrl->vport, &queue_id);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dtb_queue_request");

	p_dev_init_ctrl->queue_id = queue_id;

	rc = zxdh_np_dtb_user_info_set(dev_id, queue_id,
		p_dev_init_ctrl->vport, p_dev_init_ctrl->vector);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_dtb_user_info_set");

	zxdh_np_dtb_down_channel_addr_set(dev_id, queue_id,
		p_dev_init_ctrl->down_phy_addr, p_dev_init_ctrl->down_vir_addr, 0);

	zxdh_np_dtb_dump_channel_addr_set(dev_id, queue_id,
		p_dev_init_ctrl->dump_phy_addr, p_dev_init_ctrl->dump_vir_addr, 0);

	return ZXDH_OK;
}

int
zxdh_np_host_init(uint32_t dev_id,
		ZXDH_DEV_INIT_CTRL_T *p_dev_init_ctrl)
{
	ZXDH_SYS_INIT_CTRL_T sys_init_ctrl = {0};
	uint32_t rc;
	uint64_t agent_addr;
	uint32_t bar_msg_num = 0;

	ZXDH_COMM_CHECK_DEV_POINT(dev_id, p_dev_init_ctrl);

	sys_init_ctrl.flags = (ZXDH_DEV_ACCESS_TYPE_PCIE << 0) | (ZXDH_DEV_AGENT_ENABLE << 10);
	sys_init_ctrl.pcie_vir_baddr = zxdh_np_addr_calc(p_dev_init_ctrl->pcie_vir_addr,
		p_dev_init_ctrl->np_bar_offset);
	sys_init_ctrl.device_type = ZXDH_DEV_TYPE_CHIP;

	rc = zxdh_np_base_soft_init(dev_id, &sys_init_ctrl);
	ZXDH_COMM_CHECK_RC_NO_ASSERT(rc, "zxdh_base_soft_init");

	zxdh_np_dev_vport_set(dev_id, p_dev_init_ctrl->vport);

	agent_addr = ZXDH_PCIE_AGENT_ADDR_OFFSET + p_dev_init_ctrl->pcie_vir_addr;
	zxdh_np_dev_agent_addr_set(dev_id, agent_addr);

	zxdh_np_pf_fw_compatible_addr_set(dev_id, p_dev_init_ctrl->pcie_vir_addr);

	rc = zxdh_np_np_sdk_version_compatible_check(dev_id);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_np_sdk_version_compatible_check");

	rc = zxdh_np_pcie_bar_msg_num_get(dev_id, &bar_msg_num);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_pcie_bar_msg_num_get");

	zxdh_np_dev_fw_bar_msg_num_set(dev_id, bar_msg_num);

	rc = zxdh_np_apt_dtb_res_init(dev_id, p_dev_init_ctrl);
	ZXDH_COMM_CHECK_DEV_RC(dev_id, rc, "zxdh_np_apt_dtb_res_init");

	PMD_DRV_LOG(INFO, "host init done, queue_id = %u", p_dev_init_ctrl->queue_id);

	return 0;
}

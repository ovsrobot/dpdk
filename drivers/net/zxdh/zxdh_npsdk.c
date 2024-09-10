/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#include <rte_common.h>
#include "zxdh_npsdk.h"

int dpp_dtb_hash_offline_delete(uint32_t dev_id __rte_unused,
								uint32_t queue_id __rte_unused,
								uint32_t sdt_no __rte_unused,
								uint32_t flush_mode __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_dtb_hash_online_delete(uint32_t dev_id __rte_unused,
							   uint32_t queue_id __rte_unused,
							   uint32_t sdt_no __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_hash_res_get(uint32_t type __rte_unused,
				DPP_APT_HASH_RES_INIT_T *HashResInit __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_eram_res_get(uint32_t type __rte_unused,
				DPP_APT_ERAM_RES_INIT_T *EramResInit __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_stat_res_get(uint32_t type __rte_unused,
				DPP_APT_STAT_RES_INIT_T *StatResInit __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_hash_global_res_init(uint32_t dev_id __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_hash_func_res_init(uint32_t dev_id __rte_unused,
					uint32_t func_num __rte_unused,
					DPP_APT_HASH_FUNC_RES_T *HashFuncRes __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_hash_bulk_res_init(uint32_t dev_id __rte_unused,
					uint32_t bulk_num __rte_unused,
					DPP_APT_HASH_BULK_RES_T *BulkRes __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_hash_tbl_res_init(uint32_t dev_id __rte_unused,
					uint32_t tbl_num __rte_unused,
					DPP_APT_HASH_TABLE_T *HashTbl __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_apt_eram_res_init(uint32_t dev_id __rte_unused,
				uint32_t tbl_num __rte_unused,
				DPP_APT_ERAM_TABLE_T *EramTbl __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_stat_ppu_eram_baddr_set(uint32_t dev_id __rte_unused,
					uint32_t ppu_eram_baddr __rte_unused)
{
	/* todo provided later */
	return 0;
}
int dpp_stat_ppu_eram_depth_set(uint32_t dev_id __rte_unused,
					uint32_t ppu_eram_depth __rte_unused)
{
	/* todo provided later */
	return 0;
}
int dpp_se_cmmu_smmu1_cfg_set(uint32_t dev_id __rte_unused,
					uint32_t base_addr __rte_unused)
{
	/* todo provided later */
	return 0;
}
int dpp_stat_ppu_ddr_baddr_set(uint32_t dev_id __rte_unused,
					uint32_t ppu_ddr_baddr __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_host_np_init(uint32_t dev_id __rte_unused,
			DPP_DEV_INIT_CTRL_T *p_dev_init_ctrl __rte_unused)
{
	/* todo provided later */
	return 0;
}
int dpp_np_online_uninstall(uint32_t dev_id __rte_unused,
			char *port_name __rte_unused,
			uint32_t queue_id __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_dtb_stat_ppu_cnt_get(uint32_t dev_id __rte_unused,
			 uint32_t queue_id __rte_unused,
			 STAT_CNT_MODE_E rd_mode __rte_unused,
			 uint32_t index __rte_unused,
			 uint32_t *p_data __rte_unused)
{
	/* todo provided later */
	return 0;
}

int dpp_dtb_entry_get(uint32_t dev_id __rte_unused,
		 uint32_t queue_id __rte_unused,
		 DPP_DTB_USER_ENTRY_T *GetEntry __rte_unused,
		 uint32_t srh_mode __rte_unused)
{
	/* todo provided later */
	return 0;
}
int dpp_dtb_table_entry_write(uint32_t dev_id __rte_unused,
			uint32_t queue_id __rte_unused,
			uint32_t entryNum __rte_unused,
			DPP_DTB_USER_ENTRY_T *DownEntrys __rte_unused)
{
	/* todo provided later */
	return 0;
}
int dpp_dtb_table_entry_delete(uint32_t dev_id __rte_unused,
			 uint32_t queue_id __rte_unused,
			 uint32_t entryNum __rte_unused,
			 DPP_DTB_USER_ENTRY_T *DeleteEntrys __rte_unused)
{
	/* todo provided later */
	return 0;
}



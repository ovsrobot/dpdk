/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_MGMT_H_
#define _SPNIC_MGMT_H_

#define SPNIC_MSG_HANDLER_RES	(-1)

/* Cmdq module type */
enum spnic_mod_type {
	SPNIC_MOD_COMM = 0, /* HW communication module */
	SPNIC_MOD_L2NIC = 1, /* L2NIC module */
	SPNIC_MOD_ROCE = 2,
	SPNIC_MOD_PLOG = 3,
	SPNIC_MOD_TOE = 4,
	SPNIC_MOD_FLR = 5,
	SPNIC_MOD_FC = 6,
	SPNIC_MOD_CFGM = 7, /* Configuration module */
	SPNIC_MOD_CQM = 8,
	SPNIC_MOD_VSWITCH = 9,
	COMM_MOD_FC = 10,
	SPNIC_MOD_OVS = 11,
	SPNIC_MOD_DSW = 12,
	SPNIC_MOD_MIGRATE = 13,
	SPNIC_MOD_HILINK = 14,
	SPNIC_MOD_CRYPT = 15, /* Secure crypto module */
	SPNIC_MOD_HW_MAX = 16, /* Hardware max module id */

	/* Software module id, for PF/VF and multi-host */
	SPNIC_MOD_SW_FUNC = 17,
	SPNIC_MOD_IOE = 18,
	SPNIC_MOD_MAX
};

#endif /* _SPNIC_MGMT_H_ */

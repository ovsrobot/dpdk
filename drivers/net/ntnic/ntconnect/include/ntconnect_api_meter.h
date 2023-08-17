/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_METER_FILTER_H_
#define _NTCONNECT_METER_FILTER_H_

#define FLOW_COOKIE 0x12344321

/*
 * Create structures allocating the space to carry through ntconnect interface
 */

#define MAX_PATH_LEN 128

enum ntconn_meter_err_e {
	NTCONN_METER_ERR_NONE = 0,
	NTCONN_METER_ERR_INTERNAL_ERROR = 0x100,
	NTCONN_METER_ERR_INVALID_PORT,
	NTCONN_METER_ERR_UNEXPECTED_VIRTIO_PATH,
	NTCONN_METER_ERR_PROFILE_ID,
	NTCONN_METER_ERR_POLICY_ID,
	NTCONN_METER_ERR_METER_ID,
};

enum ntconn_meter_command_e {
	UNKNOWN_CMD,
	ADD_PROFILE,
	DEL_PROFILE,
	ADD_POLICY,
	DEL_POLICY,
	CREATE_MTR,
	DEL_MTR
};

#define ERR_MSG_LEN 128LLU

struct meter_error_return_s {
	enum rte_mtr_error_type type;
	int status;
	char err_msg[ERR_MSG_LEN];
};

struct meter_setup_s {
	uint8_t vport;
	uint32_t id;
	int shared;
	union {
		struct rte_mtr_meter_profile profile;
		struct {
			struct rte_mtr_meter_policy_params policy;
			struct rte_flow_action actions_green[2];
			struct rte_flow_action actions_yellow[2];
			struct rte_flow_action actions_red[2];
		} p;
		struct rte_mtr_params mtr_params;
	};
};

struct meter_get_stat_s {
	uint8_t vport;
	uint32_t mtr_id;
	int clear;
};

struct meter_return_stat_s {
	struct rte_mtr_stats stats;
	uint64_t stats_mask;
};

struct meter_setup_ptr_s {
	uint32_t id;
	int shared;
	union {
		struct rte_mtr_meter_profile *profile;
		struct rte_mtr_meter_policy_params *policy;
		struct rte_mtr_params *mtr_params;
	};
};

struct meter_return_s {
	int status;
};

struct meter_capabilities_return_s {
	struct rte_mtr_capabilities cap;
};

#endif /* _NTCONNECT_METER_FILTER_H_ */

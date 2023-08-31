/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <errno.h>
#include "ntnic_ethdev.h"
#include "ntconnect.h"
#include "ntos_system.h"
#include "ntconn_modules.h"
#include "ntconn_mod_helper.h"
#include "nt_util.h"
#include "ntlog.h"
#include "ntnic_vf_vdpa.h"

#include "ntconnect_api_meter.h"
#include "flow_api_profile_inline.h"

#include <rte_errno.h>
#include <rte_mtr.h>
#include <rte_mtr_driver.h>

#define NTCONN_METER_VERSION_MAJOR 0U
#define NTCONN_METER_VERSION_MINOR 1U

#define this_module_name "meter"

#define MAX_CLIENTS 32

#define UNUSED __rte_unused

static struct meter_hdl_s {
	struct drv_s *drv;
} meter_hdl[MAX_CLIENTS];

static ntconn_err_t ntconn_err[] = {
	{ NTCONN_METER_ERR_NONE, "Success" },
	{ NTCONN_METER_ERR_INTERNAL_ERROR, "Internal error" },
	{ NTCONN_METER_ERR_INVALID_PORT, "Invalid virtual port" },
	{ NTCONN_METER_ERR_PROFILE_ID, "Profile ID out of range" },
	{ NTCONN_METER_ERR_POLICY_ID, "Policy ID out of range" },
	{ NTCONN_METER_ERR_METER_ID, "Meter ID out of range" },
	{ -1, NULL }
};

/********************************************************************/
/* Get error message corresponding to the error code                */
/********************************************************************/
static const char *get_error_msg(uint32_t err_code)
{
	int idx = 0;

	if (err_code < NTCONN_METER_ERR_INTERNAL_ERROR) {
		const ntconn_err_t *err_msg = get_ntconn_error(err_code);

		return err_msg->err_text;
	}
	while (ntconn_err[idx].err_code != (uint32_t)-1 &&
			ntconn_err[idx].err_code != err_code)
		idx++;
	if (ntconn_err[idx].err_code == (uint32_t)-1)
		idx = 1;
	return ntconn_err[idx].err_text;
}

/*
 * Filter functions
 */
static int func_meter_get_capabilities(void *hdl, int client_id,
				       struct ntconn_header_s *hdr, char **data,
				       int *len);
static int func_meter_setup(void *hdl, int client_id,
			    struct ntconn_header_s *hdr, char **data, int *len);
static int func_meter_read(void *hdl, int client_id,
			   struct ntconn_header_s *hdr, char **data, int *len);
static struct func_s adapter_entry_funcs[] = {
	{ "capabilities", NULL, func_meter_get_capabilities },
	{ "setup", NULL, func_meter_setup },
	{ "read", NULL, func_meter_read },
	{ NULL, NULL, NULL },
};

/**********************************************************************/
/* copy error message corresponding to the error code to error struct */
/**********************************************************************/
static void copy_mtr_error(struct rte_mtr_error *error, uint32_t err)
{
	error->type = RTE_MTR_ERROR_TYPE_UNSPECIFIED;
	error->message = get_error_msg(err);
	error->cause = NULL;
}

static int func_meter_get_capabilities(void *hdl _unused, int client_id _unused,
				       struct ntconn_header_s *hdr _unused,
				       char **data, int *len)
{
	char *saveptr;
	uint8_t vport = 0;
	uint8_t port = 0;
	int status;
	struct rte_mtr_capabilities cap;
	struct rte_mtr_error error;

#ifdef DEBUG_METER
	NT_LOG(DBG, NTCONNECT, "%s: \"%s\"\n", __func__, *data);
#endif

	char *tok = strtok_r(*data, ",", &saveptr);

	if (tok) {
		int length = strlen(tok);

		if (length > 6 && memcmp(tok, "vport=", 6) == 0)
			vport = atoi(tok + 6);
	}
#ifdef DEBUG_METER
	NT_LOG(DBG, NTCONNECT, "vport=%u\n", vport);
#endif

	if (vport == 0 || vport > 64) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Virtual port is invalid");
		copy_mtr_error(&error, NTCONN_METER_ERR_INVALID_PORT);
		status = -ENODEV;
		goto error_get_capa;
	}

	port = vport & 1;
	status = rte_mtr_capabilities_get(port, &cap, &error);
	if (status == 0) {
		/* Handle success by copying the return values to the return struct */
		*data = malloc(sizeof(struct meter_capabilities_return_s));
		if (!*data)
			goto error_get_capa_malloc;
		struct meter_capabilities_return_s *return_value =
			(struct meter_capabilities_return_s *)*data;
		*len = sizeof(struct meter_capabilities_return_s);
		memcpy(&return_value->cap, &cap,
		       sizeof(struct rte_mtr_capabilities));
		return REQUEST_OK;
	}

error_get_capa:

	/* Handle errors by copy errors to the error struct */
	NT_LOG(ERR, NTCONNECT, "Failed to get capabilities for port %u (%u)",
	       port, vport);
	*data = malloc(sizeof(struct meter_error_return_s));
	if (!*data)
		goto error_get_capa_malloc;
	struct meter_error_return_s *return_value =
		(struct meter_error_return_s *)*data;
	*len = sizeof(struct meter_error_return_s);
	return_value->status = status;
	return_value->type = error.type;
	strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);
	return REQUEST_OK;

error_get_capa_malloc:

	*len = 0;
	return REQUEST_ERR;
}

static int func_meter_setup(void *hdl _unused, int client_id _unused,
			    struct ntconn_header_s *hdr, char **data, int *len)
{
	char *saveptr;
	uint8_t port;
	uint32_t max_id;
	int status;
	struct rte_mtr_error error;
	int command = UNKNOWN_CMD;

#ifdef DEBUG_METER
	NT_LOG(DBG, NTCONNECT, "%s: \"%s\"\n", __func__, *data);
#endif

	if (hdr->blob_len != sizeof(struct meter_setup_s)) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Error: Profile data size is illegal");
		copy_mtr_error(&error, NTCONN_ERR_CODE_INVALID_REQUEST);
		status = -EINTR;
		goto error_meter_setup;
	}

	/* Get the data blob containing the data for the meter function */
	struct meter_setup_s *cpy_data =
		(struct meter_setup_s *)&(*data)[hdr->len];

	if (cpy_data->vport < 4 || cpy_data->vport > 128) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Virtual port is invalid");
		copy_mtr_error(&error, NTCONN_METER_ERR_INVALID_PORT);
		status = -ENODEV;
		goto error_meter_setup;
	}

	char *tok = strtok_r(*data, ",", &saveptr);

	if (tok) {
		int length = strlen(tok);

		if (length == 6) {
			if (memcmp(tok, "addpro", 6) == 0)
				command = ADD_PROFILE;

			else if (memcmp(tok, "delpro", 6) == 0)
				command = DEL_PROFILE;

			else if (memcmp(tok, "addpol", 6) == 0)
				command = ADD_POLICY;

			else if (memcmp(tok, "delpol", 6) == 0)
				command = DEL_POLICY;

			else if (memcmp(tok, "crtmtr", 6) == 0)
				command = CREATE_MTR;

			else if (memcmp(tok, "delmtr", 6) == 0)
				command = DEL_MTR;
		}
	}

	if (command == UNKNOWN_CMD) {
		NT_LOG(ERR, NTCONNECT, "Error: Invalid command");
		copy_mtr_error(&error, NTCONN_ERR_CODE_INVALID_REQUEST);
		status = -EINVAL;
		goto error_meter_setup;
	}

	/* Port will be either 0 or 1 depending on the VF. */
	port = cpy_data->vport & 1;

	switch (command) {
	case ADD_PROFILE:
		max_id = flow_mtr_meter_policy_n_max() / (RTE_MAX_ETHPORTS - 2);
		if (cpy_data->id > max_id) {
			NT_LOG(ERR, NTCONNECT,
			       "Error: Profile ID %u out of range. Max value is %u",
			       cpy_data->id, max_id);
			copy_mtr_error(&error, NTCONN_METER_ERR_PROFILE_ID);
			status = -EINVAL;
			goto error_meter_setup;
		}
		cpy_data->id = ((cpy_data->vport - 4) * max_id) + cpy_data->id;
		status = rte_mtr_meter_profile_add(port, cpy_data->id,
						   &cpy_data->profile, &error);
		if (status != 0) {
			NT_LOG(ERR, NTCONNECT,
			       "Failed to add profile for port %u (%u)", port,
			       cpy_data->vport);
		}
		break;
	case DEL_PROFILE:
		max_id = flow_mtr_meter_policy_n_max() / (RTE_MAX_ETHPORTS - 2);
		if (cpy_data->id > max_id) {
			NT_LOG(ERR, NTCONNECT,
			       "Error: Profile ID %u out of range. Max value is %u",
			       cpy_data->id, max_id);
			copy_mtr_error(&error, NTCONN_METER_ERR_PROFILE_ID);
			status = -EINVAL;
			goto error_meter_setup;
		}
		cpy_data->id = ((cpy_data->vport - 4) * max_id) + cpy_data->id;
		status = rte_mtr_meter_profile_delete(port, cpy_data->id,
						      &error);
		if (status != 0) {
			NT_LOG(ERR, NTCONNECT,
			       "Failed to delete profile for port %u (%u)",
			       port, cpy_data->vport);
		}
		break;
	case ADD_POLICY:
		max_id = flow_mtr_meter_policy_n_max() / (RTE_MAX_ETHPORTS - 2);
		if (cpy_data->id > max_id) {
			NT_LOG(ERR, NTCONNECT,
			       "Error: Policy ID %u out of range. Max value is %u",
			       cpy_data->id, max_id);
			copy_mtr_error(&error, NTCONN_METER_ERR_POLICY_ID);
			status = -EINVAL;
			goto error_meter_setup;
		}
		cpy_data->id = ((cpy_data->vport - 4) * max_id) + cpy_data->id;
		cpy_data->p.policy.actions[RTE_COLOR_GREEN] =
			cpy_data->p.actions_green;
		cpy_data->p.policy.actions[RTE_COLOR_YELLOW] =
			cpy_data->p.actions_yellow;
		cpy_data->p.policy.actions[RTE_COLOR_RED] =
			cpy_data->p.actions_red;
		status = rte_mtr_meter_policy_add(port, cpy_data->id,
						  &cpy_data->p.policy, &error);
		if (status != 0) {
			NT_LOG(ERR, NTCONNECT,
			       "Failed to add policy for port %u (%u)", port,
			       cpy_data->vport);
		}
		break;
	case DEL_POLICY:
		max_id = flow_mtr_meter_policy_n_max() / (RTE_MAX_ETHPORTS - 2);
		if (cpy_data->id > max_id) {
			NT_LOG(ERR, NTCONNECT,
			       "Error: Policy ID %u out of range. Max value is %u",
			       cpy_data->id, max_id);
			copy_mtr_error(&error, NTCONN_METER_ERR_POLICY_ID);
			status = -EINVAL;
			goto error_meter_setup;
		}
		cpy_data->id = ((cpy_data->vport - 4) * max_id) + cpy_data->id;
		status =
			rte_mtr_meter_policy_delete(port, cpy_data->id, &error);
		if (status != 0) {
			NT_LOG(ERR, NTCONNECT,
			       "Failed to delete policy for port %u (%u)", port,
			       cpy_data->vport);
		}
		break;
	case CREATE_MTR:
		max_id = flow_mtr_meters_supported() / (RTE_MAX_ETHPORTS - 2);
		if (cpy_data->id > max_id) {
			NT_LOG(ERR, NTCONNECT,
			       "Error: Meter ID %u out of range. Max value is %u",
			       cpy_data->id, max_id);
			copy_mtr_error(&error, NTCONN_METER_ERR_METER_ID);
			status = -EINVAL;
			goto error_meter_setup;
		}
		cpy_data->id = ((cpy_data->vport - 4) * max_id) + cpy_data->id;
		cpy_data->mtr_params.meter_profile_id =
			((cpy_data->vport - 4) *
			 (flow_mtr_meter_policy_n_max() /
			  (RTE_MAX_ETHPORTS - 2))) +
			cpy_data->mtr_params.meter_profile_id;
		cpy_data->mtr_params.meter_policy_id =
			((cpy_data->vport - 4) *
			 (flow_mtr_meter_policy_n_max() /
			  (RTE_MAX_ETHPORTS - 2))) +
			cpy_data->mtr_params.meter_policy_id;
		status = rte_mtr_create(port, cpy_data->id,
					&cpy_data->mtr_params, cpy_data->shared,
					&error);
		if (status != 0) {
			NT_LOG(ERR, NTCONNECT,
			       "Failed to create meter for port %u (%u)", port,
			       cpy_data->vport);
		}
		break;
	case DEL_MTR:
		max_id = flow_mtr_meters_supported() / (RTE_MAX_ETHPORTS - 2);
		if (cpy_data->id > max_id) {
			NT_LOG(ERR, NTCONNECT,
			       "Error: Meter ID %u out of range. Max value is %u",
			       cpy_data->id, max_id);
			copy_mtr_error(&error, NTCONN_METER_ERR_METER_ID);
			status = -EINVAL;
			goto error_meter_setup;
		}
		cpy_data->id = ((cpy_data->vport - 4) * max_id) + cpy_data->id;
		status = rte_mtr_destroy(port, cpy_data->id, &error);
		if (status != 0) {
			NT_LOG(ERR, NTCONNECT,
			       "Failed to destroy meter for port %u (%u)", port,
			       cpy_data->vport);
		}
		break;
	}

	if (status == 0) {
		/* Handle success by copying the return values to the return struct */
		*data = malloc(sizeof(struct meter_return_s));
		if (!*data)
			goto error_meter_setup_malloc;
		struct meter_return_s *return_value =
			(struct meter_return_s *)*data;
		*len = sizeof(struct meter_return_s);
		return_value->status = 0;
		return REQUEST_OK;
	}

error_meter_setup:

	/* Handle errors by copy errors to the error struct */
	 *data = malloc(sizeof(struct meter_error_return_s));
	if (!*data)
		goto error_meter_setup_malloc;
	struct meter_error_return_s *return_value =
		(struct meter_error_return_s *)*data;
	*len = sizeof(struct meter_error_return_s);
	return_value->status = status;
	return_value->type = error.type;
	strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);
	return REQUEST_OK;

error_meter_setup_malloc:

	*len = 0;
	return REQUEST_ERR;
}

static int func_meter_read(void *hdl _unused, int client_id _unused,
			   struct ntconn_header_s *hdr, char **data, int *len)
{
	uint8_t port = 0;
	int status;
	struct rte_mtr_error error;
	struct rte_mtr_stats stats;
	uint64_t stats_mask;

#ifdef DEBUG_METER
	NT_LOG(DBG, NTCONNECT, "%s: [%s:%u] enter\n", __func__, __FILE__, __LINE__);
#endif

	if (hdr->blob_len != sizeof(struct meter_get_stat_s)) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT,
		       "Error: Read meter stats data size is illegal");
		copy_mtr_error(&error, NTCONN_ERR_CODE_INVALID_REQUEST);
		status = -EINTR;
		goto error_meter_read;
	}

	/* Get the data blob containing the data for the meter function */
	struct meter_get_stat_s *cpy_data =
		(struct meter_get_stat_s *)&(*data)[hdr->len];

	if (cpy_data->vport < 4 || cpy_data->vport > 128) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Virtual port is invalid");
		copy_mtr_error(&error, NTCONN_METER_ERR_INVALID_PORT);
		status = -ENODEV;
		goto error_meter_read;
	}

	port = cpy_data->vport & 1;
	cpy_data->mtr_id =
		((cpy_data->vport - 4) *
		 (flow_mtr_meters_supported() / (RTE_MAX_ETHPORTS - 2))) +
		cpy_data->mtr_id;
	status = rte_mtr_stats_read(port, cpy_data->mtr_id, &stats, &stats_mask,
				    cpy_data->clear, &error);
	if (status == 0) {
		/* Handle success by copying the return values to the return struct */
		*data = malloc(sizeof(struct meter_return_stat_s));
		if (!*data)
			goto error_meter_read_malloc;
		struct meter_return_stat_s *return_value =
			(struct meter_return_stat_s *)*data;
		*len = sizeof(struct meter_return_stat_s);
		return_value->stats_mask = stats_mask;
		memcpy(&return_value->stats, &stats,
		       sizeof(struct rte_mtr_stats));
		return REQUEST_OK;
	}

error_meter_read:
	/* Handle errors by copy errors to the error struct */
	NT_LOG(ERR, NTCONNECT, "Failed to read meter stats");
	*data = malloc(sizeof(struct meter_error_return_s));
	if (!*data)
		goto error_meter_read_malloc;
	struct meter_error_return_s *return_value =
		(struct meter_error_return_s *)*data;
	*len = sizeof(struct meter_error_return_s);
	strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);
	return_value->status = status;
	return_value->type = error.type;
	return REQUEST_OK;

error_meter_read_malloc:
	*len = 0;
	return REQUEST_ERR;
}

static int meter_request(void *hdl, int client_id _unused,
			 struct ntconn_header_s *hdr, char *function,
			 char **data, int *len)
{
	return execute_function(this_module_name, hdl, client_id, hdr, function,
				adapter_entry_funcs, data, len, 0);
}

static void meter_free_data(void *hdl _unused, char *data)
{
	if (data)
		free(data);
}

static void meter_client_cleanup(void *hdl _unused, int client_id _unused)
{
	/* Nothing to do */
}

static const ntconnapi_t ntconn_meter_op = { this_module_name,
					     NTCONN_METER_VERSION_MAJOR,
					     NTCONN_METER_VERSION_MINOR,
					     meter_request,
					     meter_free_data,
					     meter_client_cleanup
					   };

int ntconn_meter_register(struct drv_s *drv)
{
	int i;

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (meter_hdl[i].drv == NULL)
			break;
	}
	if (i == MAX_CLIENTS) {
		NT_LOG(ERR, NTCONNECT,
		       "Cannot register more adapters into NtConnect framework");
		return -1;
	}

	meter_hdl[i].drv = drv;
	return register_ntconn_mod(&drv->p_dev->addr, (void *)&meter_hdl[i],
				   &ntconn_meter_op);
}

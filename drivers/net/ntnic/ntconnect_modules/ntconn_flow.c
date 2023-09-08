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

#include "ntconnect_api_flow.h"
#include "ntconnect_api_meter.h"
#include "stream_binary_flow_api.h"

#include <rte_errno.h>
#include "flow_api.h"

#define DEBUG_FLOW 1

#define NTCONN_FLOW_VERSION_MAJOR 0U
#define NTCONN_FLOW_VERSION_MINOR 1U

#define this_module_name "filter"

#define IN_PORT_TOK "in_port="
#define VPATH_TOK "vpath="

#define MAX_CLIENTS 32

#define UNUSED __rte_unused

static struct flow_hdl_s {
	struct drv_s *drv;
} flow_hdl[MAX_CLIENTS];

#define MAX_PORTS 64
static struct port_to_eth_s {
	struct flow_eth_dev *flw_dev;
	uint32_t forced_vlan_vid;
	uint32_t caller_id;
} port_eth[MAX_PORTS];

static ntconn_err_t ntconn_err[] = {
	{ NTCONN_FLOW_ERR_NONE, "Success" },
	{ NTCONN_FLOW_ERR_INTERNAL_ERROR, "Internal error" },
	{ NTCONN_FLOW_ERR_PORT_IS_NOT_INITIALIZED, "Port is not initialized" },
	{ NTCONN_FLOW_ERR_UNEXPECTED_VIRTIO_PATH, "Unexpected virtio path" },
	{ NTCONN_FLOW_ERR_TO_MANY_FLOWS, "To many flows" },
	{ NTCONN_FLOW_ERR_INVALID_PORT, "Invalid port" },
	{ NTCONN_FLOW_ERR_NOT_YET_IMPLEMENTED, "Function not yet implemented" },
	{ NTCONN_FLOW_ERR_UNSUPPORTED_ADAPTER, "Adapter is not supported" },
	{ NTCONN_FLOW_ERR_NO_VF_QUEUES, "No queues for the VF is found" },
	{ -1, NULL }
};

static const char *get_error_msg(enum ntconn_flow_err_e err_code)
{
	int idx = 0;

	while (ntconn_err[idx].err_code != (uint32_t)-1 &&
			ntconn_err[idx].err_code != err_code)
		idx++;
	if (ntconn_err[idx].err_code == (uint32_t)-1)
		idx = 1;

	return ntconn_err[idx].err_text;
}

static inline int ntconn_flow_err_reply_status(char **data, int *len,
		enum ntconn_flow_err_e code,
		int err)
{
	*data = malloc(sizeof(struct flow_return_s));
	if (*data) {
		struct flow_return_s *return_value =
			(struct flow_return_s *)*data;
		*len = sizeof(struct flow_return_s);
		return_value->status = err;
		return_value->type = FLOW_ERROR_GENERAL;
		const char *err_msg = get_error_msg(code);

		memcpy(return_value->err_msg, err_msg,
		       RTE_MIN(strlen(err_msg), ERR_MSG_LEN));
		return REQUEST_OK;
	}
	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory");
	return REQUEST_ERR;
}

static inline int ntconn_flow_err_status(char **data, int *len, int err)
{
	*data = malloc(sizeof(struct flow_return_s));
	if (*data) {
		struct flow_return_s *return_value =
			(struct flow_return_s *)*data;
		*len = sizeof(struct flow_return_s);
		return_value->status = err;
		return_value->type = FLOW_ERROR_GENERAL;
		const char *err_msg =
			get_error_msg(NTCONN_FLOW_ERR_INTERNAL_ERROR);
		strlcpy(return_value->err_msg, err_msg, ERR_MSG_LEN);
		return REQUEST_OK;
	}
	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory");
	return REQUEST_ERR;
}

/*
 * Filter functions
 */
static int func_flow_create(void *hdl, int client_id,
			    struct ntconn_header_s *hdr, char **data, int *len);
static int func_flow_validate(void *hdl, int client_id,
			      struct ntconn_header_s *hdr, char **data,
			      int *len);
static int func_flow_destroy(void *hdl, int client_id,
			     struct ntconn_header_s *hdr, char **data,
			     int *len);
static int func_flow_flush(void *hdl, int client_id,
			   struct ntconn_header_s *hdr, char **data, int *len);
static int func_flow_query(void *hdl, int client_id,
			   struct ntconn_header_s *hdr, char **data, int *len);
static int func_flow_setport(void *hdl, int client_id,
			     struct ntconn_header_s *hdr, char **data,
			     int *len);
static struct func_s adapter_entry_funcs[] = {
	{ "setport", NULL, func_flow_setport },
	{ "create", NULL, func_flow_create },
	{ "validate", NULL, func_flow_validate },
	{ "destroy", NULL, func_flow_destroy },
	{ "flush", NULL, func_flow_flush },
	{ "query", NULL, func_flow_query },
	{ NULL, NULL, NULL },
};

static int copy_return_status(char **data, int *len, int status,
			      struct flow_error *error)
{
	*data = malloc(sizeof(struct flow_return_s));
	if (*data) {
		struct flow_return_s *return_value =
			(struct flow_return_s *)*data;
		*len = sizeof(struct flow_return_s);

		return_value->status = status;
		return_value->type = error->type;
		strlcpy(return_value->err_msg, error->message, ERR_MSG_LEN);
		return REQUEST_OK;
	}
	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory %s",
	       __func__);
	return REQUEST_ERR;
}

static void set_error(struct flow_error *error)
{
	error->type = FLOW_ERROR_SUCCESS;
	error->message = "Operation successfully completed";
}

static int func_flow_setport(void *hdl _unused, int client_id _unused,
			     struct ntconn_header_s *hdr _unused, char **data,
			     int *len)
{
	uint32_t i;
	struct flow_error error;
	uint32_t nb_port;
	uint8_t in_port = MAX_PORTS;
	char vpath[MAX_PATH_LEN];
	char *saveptr;

	set_error(&error);

	nb_port = rte_eth_dev_count_avail();

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "%s: \"%s\"\n", __func__, *data);
	NT_LOG(DBG, NTCONNECT, "Number of ports: %u\n", nb_port);
#endif

	char *tok = strtok_r(*data, ",", &saveptr);

	if (tok) {
		size_t length = strlen(tok);
		if (length > strlen(IN_PORT_TOK) && memcmp(tok, IN_PORT_TOK,
							   strlen(IN_PORT_TOK)) == 0)
			in_port = atoi(tok + strlen(IN_PORT_TOK));
	}
#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "in_port:          %u\n", in_port);
#endif

	tok = strtok_r(NULL, ",", &saveptr);
	if (tok) {
		size_t length = strlen(tok);
		if (length > strlen(VPATH_TOK) && memcmp(tok, VPATH_TOK, strlen(VPATH_TOK)) == 0)
			strlcpy(vpath, tok + strlen(VPATH_TOK), MAX_PATH_LEN);
	}
#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "vpath:           %s\n", vpath);
#endif

	/* Check that the wanted ports are valid ports */
	if (in_port >= nb_port) {
		NT_LOG(ERR, NTCONNECT, "port out of range");
		return ntconn_flow_err_status(data, len, ENODEV);
	}

	struct pmd_internals *vp_internals = vp_path_instance_ready(vpath);

	if (!vp_internals) {
		NT_LOG(ERR, NTCONNECT, "Failed to get VF device");
		return ntconn_flow_err_status(data, len, ENODEV);
	}

	/* Get flow device */
	port_eth[in_port].flw_dev = vp_internals->flw_dev;

	if (port_eth[in_port].flw_dev == NULL) {
		NT_LOG(ERR, NTCONNECT, "Failed to get eth device");
		return ntconn_flow_err_status(data, len, ENODEV);
	}

	/* Only INLINE is supported */
	if (vp_internals->flw_dev->ndev->flow_profile !=
			FLOW_ETH_DEV_PROFILE_INLINE) {
		/* Only inline profile is supported */
		NT_LOG(ERR, NTCONNECT, "Adapter is not supported");
		return ntconn_flow_err_status(data, len, ENODEV);
	}

	if (vp_internals->vpq_nb_vq == 0) {
		NT_LOG(ERR, NTCONNECT, "No queues for the VF is found");
		return ntconn_flow_err_status(data, len, ENODEV);
	}

	/* Server and client must agree of the virtual port number */
	if (vp_internals->port != (in_port + 4U)) {
		NT_LOG(ERR, NTCONNECT,
		       "Internal error: Virtual port out of sync");
		return ntconn_flow_err_status(data, len, ENODEV);
	}

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "vport:           %u\n", vp_internals->port);
	NT_LOG(DBG, NTCONNECT, "vlan (forced):   %u\n", vp_internals->vlan);
#endif

	port_eth[in_port].caller_id = vp_internals->port;
	port_eth[in_port].forced_vlan_vid = vp_internals->vlan;

	*data = malloc(sizeof(struct flow_setport_return));
	if (*data) {
		struct flow_setport_return *return_value =
			(struct flow_setport_return *)*data;
		*len = sizeof(struct flow_setport_return);
		return_value->num_queues = vp_internals->vpq_nb_vq;

#ifdef DEBUG_FLOW
		NT_LOG(DBG, NTCONNECT, "Number of queues: %u\n",
		       vp_internals->vpq_nb_vq);
#endif
		for (i = 0; i < vp_internals->vpq_nb_vq && i < MAX_QUEUES;
				i++) {
#ifdef DEBUG_FLOW
			NT_LOG(DBG, NTCONNECT, "Queue:            %u\n",
			       vp_internals->vpq[i].id);
			NT_LOG(DBG, NTCONNECT, "HW ID:            %u\n",
			       vp_internals->vpq[i].hw_id);
#endif
			return_value->queues[i].id = vp_internals->vpq[i].id;
			return_value->queues[i].hw_id =
				vp_internals->vpq[i].hw_id;
#ifdef DEBUG_FLOW
			NT_LOG(DBG, NTCONNECT,
			       "Setup output port: %u, %04x:%02x:%02x.%x\n",
			       in_port, vp_internals->pci_dev->addr.domain,
			       vp_internals->pci_dev->addr.bus,
			       vp_internals->pci_dev->addr.devid,
			       vp_internals->pci_dev->addr.function);
#endif
		}
		return REQUEST_OK;
	}
	*len = 0;
	return REQUEST_ERR;
}

static int func_flow_flush(void *hdl _unused, int client_id _unused,
			   struct ntconn_header_s *hdr _unused, char **data,
			   int *len)
{
	struct flow_error error;
	int port = MAX_PORTS;
	int status = -1;
	char *saveptr;

	set_error(&error);

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "%s: [%s:%u] enter\n", __func__, __FILE__, __LINE__);
#endif

	char *tok = strtok_r(*data, ",", &saveptr);

	if (tok) {
		int length = strlen(tok);

		if (length > 5 && memcmp(tok, "port=", 5) == 0)
			port = atoi(tok + 5);
	}
#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "Port id=%u\n", port);
#endif

	if (port >= MAX_PORTS) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "port id out of range");
		return ntconn_flow_err_reply_status(data, len,
						    NTCONN_FLOW_ERR_INVALID_PORT,
						    ENODEV);
	}

	/* Call filter with data */
	status = flow_flush(port_eth[port].flw_dev, &error);
	return copy_return_status(data, len, status, &error);
}

static int func_flow_destroy(void *hdl _unused, int client_id _unused,
			     struct ntconn_header_s *hdr, char **data, int *len)
{
	struct flow_error error;
	int port = MAX_PORTS;
	uint64_t flow = 0;
	int status = -1;

	struct destroy_flow_ntconnect *flow_cpy =
		(struct destroy_flow_ntconnect *)&(*data)[hdr->len];

	if (hdr->blob_len != sizeof(struct destroy_flow_ntconnect)) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Error in filter data");
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_INVALID_REQUEST);
	}

#ifdef DEBUG_FLOW1
	NT_LOG(DBG, NTCONNECT, "%s: [%s:%u] enter\n", __func__, __FILE__, __LINE__);
#endif

	port = flow_cpy->port;

#ifdef DEBUG_FLOW1
	NT_LOG(DBG, NTCONNECT, "Port id=%u\n", port);
#endif

	if (port >= MAX_PORTS) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "port id out of range");
		return ntconn_flow_err_reply_status(data, len,
						    NTCONN_FLOW_ERR_INVALID_PORT,
						    ENODEV);
	}

	flow = flow_cpy->flow;

#ifdef DEBUG_FLOW1
	NT_LOG(DBG, NTCONNECT, "flow=0x%016llX\n",
	       (unsigned long long)flow);
#endif

	/* Call filter with data */
	status = flow_destroy(port_eth[port].flw_dev,
			      (struct flow_handle *)flow, &error);

	*data = malloc(sizeof(struct flow_return_s));
	if (*data) {
		struct flow_return_s *return_value =
			(struct flow_return_s *)*data;
		*len = sizeof(struct flow_return_s);

		return_value->status = status;
		return_value->type = error.type;
		strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);
		return REQUEST_OK;
	}
	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory %s",
	       __func__);
	return REQUEST_ERR;
}

enum {
	FLOW_API_FUNC_CREATE,
	FLOW_API_FUNC_VALIDATE,
};

static uint64_t make_flow_create(int func, int port,
				 struct create_flow_ntconnect *flow_cpy,
				 int *status, struct flow_error *error)
{
	struct flow_elem elem[MAX_FLOW_STREAM_ELEM];
	struct flow_action action[MAX_FLOW_STREAM_ELEM];
	struct flow_action_vxlan_encap vxlan_tun;
	struct flow_action_raw_encap encap;
	struct flow_action_raw_decap decap;
	struct flow_elem elem_tun[MAX_FLOW_STREAM_VXLAN_TUN_ELEM];
	int idx = -1;

	struct flow_attr *attr = &flow_cpy->attr;
	struct flow_elem_cpy *elem_cpy = flow_cpy->elem;
	struct flow_action_cpy *action_cpy = flow_cpy->action;

	error->type = FLOW_ERROR_GENERAL;
	error->message = "To many flows";
	*status = NTCONN_FLOW_ERR_TO_MANY_FLOWS;

	attr->caller_id = port_eth[port].caller_id;
	attr->forced_vlan_vid = port_eth[port].forced_vlan_vid;

	do {
		idx++;
		if (idx > MAX_FLOW_STREAM_ELEM)
			goto error;
		elem[idx].type = elem_cpy[idx].type;
		if (!elem_cpy[idx].spec_cpy.valid) {
			elem[idx].spec = NULL;
		} else {
			elem[idx].spec =
				(void *)&elem_cpy[idx].spec_cpy.u.start_addr;
		}
		if (!elem_cpy[idx].mask_cpy.valid) {
			elem[idx].mask = NULL;
		} else {
			elem[idx].mask =
				(void *)&elem_cpy[idx].mask_cpy.u.start_addr;
		}
	} while (elem_cpy[idx].type != FLOW_ELEM_TYPE_END);

	idx = -1;
	do {
		idx++;
		if (idx > MAX_FLOW_STREAM_ELEM)
			goto error;
		action[idx].type = action_cpy[idx].type;
		if (!action_cpy[idx].conf_cpy.valid) {
			action[idx].conf = NULL;
		} else {
			switch (action_cpy[idx].type) {
			case FLOW_ACTION_TYPE_VXLAN_ENCAP: {
				/*
				 * Special VXLAN ENCAP treatment create inner tunnel
				 * elements in action
				 */
				struct flow_elem_cpy *tun_elem_cpy =
					(struct flow_elem_cpy *)action_cpy[idx]
					.conf_cpy.u.vxlan.vxlan_tunnel;
				vxlan_tun.vxlan_tunnel = elem_tun;
				int tun_idx = -1;

				do {
					tun_idx++;
					if (tun_idx >
							MAX_FLOW_STREAM_VXLAN_TUN_ELEM) {
						error->message =
							"To many VXLAN tunnels";
						goto error;
					}
					elem_tun[tun_idx].type =
						tun_elem_cpy[tun_idx].type;
					if (!tun_elem_cpy[tun_idx]
							.spec_cpy.valid) {
						elem_tun[tun_idx].spec = NULL;
					} else {
						elem_tun[tun_idx].spec =
							(void *)&tun_elem_cpy[tun_idx]
							.spec_cpy.u
							.start_addr;
					}
					if (!tun_elem_cpy[tun_idx]
							.mask_cpy.valid) {
						elem_tun[tun_idx].mask = NULL;
					} else {
						elem_tun[tun_idx].mask =
							(void *)&tun_elem_cpy[tun_idx]
							.mask_cpy.u
							.start_addr;
					}
				} while (tun_elem_cpy[tun_idx].type !=
						FLOW_ELEM_TYPE_END);
				/* VXLAN ENCAP tunnel finished */
				action[idx].conf = &vxlan_tun;
			}
			break;
			case FLOW_ACTION_TYPE_RSS: {
				/* Need to set queue pointer */
				action_cpy[idx].conf_cpy.u.rss.rss.queue =
					(const uint16_t *)&action_cpy[idx]
					.conf_cpy.u.rss.cpy_queue;
				action[idx].conf = (void *)&action_cpy[idx]
						   .conf_cpy.u.rss.rss;
			}
			break;
			case FLOW_ACTION_TYPE_METER: {
				/* Need to convert meter ID to uniq ID for the VF */
				action_cpy[idx].conf_cpy.u.meter.mtr_id =
					((flow_mtr_meters_supported() /
					  (RTE_MAX_ETHPORTS - 2)) *
					 (flow_cpy->vport - 4)) +
					action_cpy[idx].conf_cpy.u.meter.mtr_id;
				action[idx].conf = (void *)&action_cpy[idx]
						   .conf_cpy.u.meter;
			}
			break;
			case FLOW_ACTION_TYPE_RAW_ENCAP: {
				encap.preserve = NULL;
				encap.data =
					action_cpy[idx].conf_cpy.u.encap.data;
				encap.item_count =
					action_cpy[idx]
					.conf_cpy.u.encap.item_count;
				encap.size =
					action_cpy[idx].conf_cpy.u.encap.size;

				for (int eidx = 0;
						eidx <
						action_cpy[idx].conf_cpy.u.encap.item_count;
						eidx++) {
					if (eidx > RAW_ENCAP_DECAP_ELEMS_MAX) {
						error->message =
							"To many encap items";
						goto error;
					}
					encap.items[eidx].type =
						action_cpy[idx]
						.conf_cpy.u.encap
						.item_cpy[eidx]
						.type;
					if (action_cpy[idx]
							.conf_cpy.u.encap
							.item_cpy[eidx]
							.spec_cpy.valid) {
						encap.items[eidx].spec =
							(void *)&action_cpy[idx]
							.conf_cpy.u
							.encap
							.item_cpy[eidx]
							.spec_cpy.u
							.start_addr;
					} else {
						encap.items[eidx].spec = NULL;
					}
					if (action_cpy[idx]
							.conf_cpy.u.encap
							.item_cpy[eidx]
							.mask_cpy.valid) {
						encap.items[eidx].mask =
							(void *)&action_cpy[idx]
							.conf_cpy.u
							.encap
							.item_cpy[eidx]
							.mask_cpy.u
							.start_addr;
					} else {
						encap.items[eidx].mask = NULL;
					}
				}
				action[idx].conf = &encap;
			}
			break;
			case FLOW_ACTION_TYPE_RAW_DECAP: {
				decap.data =
					action_cpy[idx].conf_cpy.u.decap.data;
				decap.item_count =
					action_cpy[idx]
					.conf_cpy.u.decap.item_count;
				decap.size =
					action_cpy[idx].conf_cpy.u.decap.size;

				for (int eidx = 0;
						eidx <
						action_cpy[idx].conf_cpy.u.decap.item_count;
						eidx++) {
					if (eidx > RAW_ENCAP_DECAP_ELEMS_MAX) {
						error->message =
							"To many decap items";
						goto error;
					}
					decap.items[eidx].type =
						action_cpy[idx]
						.conf_cpy.u.decap
						.item_cpy[eidx]
						.type;
					if (action_cpy[idx]
							.conf_cpy.u.decap
							.item_cpy[eidx]
							.spec_cpy.valid) {
						decap.items[eidx].spec =
							(void *)&action_cpy[idx]
							.conf_cpy.u
							.decap
							.item_cpy[eidx]
							.spec_cpy.u
							.start_addr;
					} else {
						decap.items[eidx].spec = NULL;
					}
					if (action_cpy[idx]
							.conf_cpy.u.decap
							.item_cpy[eidx]
							.mask_cpy.valid) {
						decap.items[eidx].mask =
							(void *)&action_cpy[idx]
							.conf_cpy.u
							.decap
							.item_cpy[eidx]
							.mask_cpy.u
							.start_addr;
					} else {
						decap.items[eidx].mask = NULL;
					}
				}
				action[idx].conf = &decap;
			}
			break;
			default: {
				/* Move conf pointer into conf_cpy data field */
				action[idx].conf =
					(void *)&action_cpy[idx]
					.conf_cpy.u.start_addr;
			}
			break;
			}
		}
	} while (action_cpy[idx].type != FLOW_ACTION_TYPE_END);

	*status = NTCONN_FLOW_ERR_NONE;
	if (func == FLOW_API_FUNC_VALIDATE) {
		*status = flow_validate(port_eth[port].flw_dev, elem, action,
					error);
		return 0ULL;
	} else {
		return (uint64_t)flow_create(port_eth[port].flw_dev, attr, elem,
					     action, error);
	}

error:
	return 0;
}

static int func_flow_create(void *hdl _unused, int client_id _unused,
			    struct ntconn_header_s *hdr, char **data, int *len)
{
	int status;
	struct flow_error error;
	uint64_t flow = 0UL;
	int port = MAX_PORTS;

	struct create_flow_ntconnect *flow_cpy =
		(struct create_flow_ntconnect *)&(*data)[hdr->len];

	if (hdr->blob_len != sizeof(struct create_flow_ntconnect)) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Error in filter data");
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_INVALID_REQUEST);
	}

	port = flow_cpy->port;

	if (port >= MAX_PORTS) {
		NT_LOG(ERR, NTCONNECT, "port id out of range");
		return ntconn_flow_err_reply_status(data, len,
						    NTCONN_FLOW_ERR_INVALID_PORT,
						    ENODEV);
	}

#ifdef DEBUG_PARSING
	int i;

	for (i = 0; i < MAX_FLOW_STREAM_ELEM; i++) {
		if (flow_cpy[i].elem[i].type == FLOW_ELEM_TYPE_END) {
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_END\n");
			break;
		}
		switch (flow_cpy->elem[i].type) {
		case FLOW_ELEM_TYPE_IPV4:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_IPV4 %i\n", i);
			NT_LOG(DBG, NTCONNECT, "     src_ip:   %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[1] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[2] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[3] & 0xFF);
			NT_LOG(DBG, NTCONNECT, "     dst_ip:   %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[1] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[2] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[3] & 0xFF);
			NT_LOG(DBG, NTCONNECT, "     src_mask: %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[1] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[2] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[3] & 0xFF);
			NT_LOG(DBG, NTCONNECT, "     dst_mask: %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[1] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[2] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[3] & 0xFF);
			break;
		case FLOW_ELEM_TYPE_ETH:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_ETH %i\n", i);
			NT_LOG(DBG, NTCONNECT,
			       "     src mac:  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[5] & 0xFF);
			NT_LOG(DBG, NTCONNECT,
			       "     dst mac:  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[5] & 0xFF);
			NT_LOG(DBG, NTCONNECT,
			       "     src mask  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[5] & 0xFF);
			NT_LOG(DBG, NTCONNECT,
			       "     dst mask  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[5] & 0xFF);
			break;
		case FLOW_ELEM_TYPE_VLAN:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_VLAN %i\n", i);
			break;
		case FLOW_ELEM_TYPE_IPV6:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_IPV6 %i\n", i);
			break;
		case FLOW_ELEM_TYPE_SCTP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_SCTP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_TCP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_TCP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_UDP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_UDP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_ICMP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_ICMP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_VXLAN:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_VXLAN %i\n", i);
			break;
		case FLOW_ELEM_TYPE_PORT_ID:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_PORT_ID %i\n",
			       i);
			break;
		default:
			NT_LOG(DBG, NTCONNECT, "Unknown item %u\n",
			       flow_cpy->elem[i].type);
			break;
		}
	}

	for (i = 0; i < MAX_FLOW_STREAM_ELEM; i++) {
		uint32_t j;

		if (flow_cpy->action[i].type == FLOW_ACTION_TYPE_END) {
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_END\n");
			break;
		}
		switch (flow_cpy->action[i].type) {
		case FLOW_ACTION_TYPE_RSS:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_RSS %i\n", i);
			NT_LOG(DBG, NTCONNECT, "     queue nb: %u\n",
			       flow_cpy->action[i].conf_cpy.u.rss.rss.queue_num);
			NT_LOG(DBG, NTCONNECT, "     queue:    ");
			for (j = 0;
					j < flow_cpy->action[i]
					.conf_cpy.u.rss.rss.queue_num &&
					j < FLOW_MAX_QUEUES;
					j++) {
				NT_LOG(DBG, NTCONNECT, "%u ",
				       flow_cpy->action[i]
				       .conf_cpy.u.rss.cpy_queue[j]);
			}
			NT_LOG(DBG, NTCONNECT, "\n");
			break;

		case FLOW_ACTION_TYPE_POP_VLAN:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_POP_VLAN %i\n",
			       i);
			break;
		case FLOW_ACTION_TYPE_PUSH_VLAN:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_PUSH_VLAN %i\n", i);
			break;
		case FLOW_ACTION_TYPE_SET_VLAN_VID:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_SET_VLAN_VID %i\n", i);
			break;
		case FLOW_ACTION_TYPE_SET_VLAN_PCP:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_SET_VLAN_PCP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_VXLAN_DECAP:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_VXLAN_DECAP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_VXLAN_ENCAP:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_VXLAN_ENCAP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_DROP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_DROP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_COUNT:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_COUNT %i\n",
			       i);
			break;
		case FLOW_ACTION_TYPE_MARK:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_MARK %i\n", i);
			break;
		case FLOW_ACTION_TYPE_PORT_ID:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_PORT_ID %i: ID=%u\n", i,
			       flow_cpy->action[i].conf_cpy.u.port_id.id);
			break;
		case FLOW_ACTION_TYPE_QUEUE:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_QUEUE %i: queue=%u\n", i,
			       flow_cpy->action[i].conf_cpy.u.queue.index);
			break;
		case FLOW_ACTION_TYPE_SET_TAG:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_SET_TAG %i: idx=%u, data=%u, mask=%X\n",
			       i, flow_cpy->action[i].conf_cpy.u.tag.index,
			       flow_cpy->action[i].conf_cpy.u.tag.data,
			       flow_cpy->action[i].conf_cpy.u.tag.mask);
			break;
		default:
			NT_LOG(DBG, NTCONNECT, "Unknown action %u\n",
			       flow_cpy->action[i].type);
			break;
		}
	}
#endif

	/* Call filter with data */
	flow = make_flow_create(FLOW_API_FUNC_CREATE, port, flow_cpy, &status,
				&error);
	if (flow) {
		*data = malloc(sizeof(struct create_flow_return_s));
		if (!*data)
			goto create_flow_error_malloc;
		struct create_flow_return_s *return_value =
			(struct create_flow_return_s *)*data;
		*len = sizeof(struct create_flow_return_s);
		return_value->flow = flow;
		return REQUEST_OK;
	}

	*data = malloc(sizeof(struct flow_error_return_s));
	if (!*data)
		goto create_flow_error_malloc;
	struct flow_error_return_s *return_value =
		(struct flow_error_return_s *)*data;
	*len = sizeof(struct flow_error_return_s);
	return_value->type = error.type;
	strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);
	return REQUEST_OK;

create_flow_error_malloc:

	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory %s", __func__);
	return REQUEST_ERR;
}

static int func_flow_validate(void *hdl _unused, int client_id _unused,
			      struct ntconn_header_s *hdr, char **data,
			      int *len)
{
	int status;
	struct flow_error error;
	int port = MAX_PORTS;

	struct create_flow_ntconnect *flow_cpy =
		(struct create_flow_ntconnect *)&(*data)[hdr->len];

	if (hdr->blob_len != sizeof(struct create_flow_ntconnect)) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Error in filter data");
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_INVALID_REQUEST);
	}

	set_error(&error);

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "func_flow_create\n");
#endif

	port = flow_cpy->port;

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "Port id=%u\n", port);
#endif

	if (port >= MAX_PORTS) {
		NT_LOG(ERR, NTCONNECT, "port id out of range");
		return ntconn_flow_err_reply_status(data, len,
			NTCONN_FLOW_ERR_INVALID_PORT, ENODEV);
	}

#ifdef DEBUG_PARSING
	int i;

	for (i = 0; i < MAX_FLOW_STREAM_ELEM; i++) {
		if (flow_cpy[i].elem[i].type == FLOW_ELEM_TYPE_END) {
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_END\n");
			break;
		}
		switch (flow_cpy->elem[i].type) {
		case FLOW_ELEM_TYPE_IPV4:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_IPV4 %i\n", i);
			NT_LOG(DBG, NTCONNECT, "     src_ip:   %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF);
			NT_LOG(DBG, NTCONNECT, "     dst_ip:   %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.spec_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF);
			NT_LOG(DBG, NTCONNECT, "     src_mask: %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.src_ip)[0] & 0xFF);
			NT_LOG(DBG, NTCONNECT, "     dst_mask: %u.%u.%u.%u\n",
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF,
				((const char *)&flow_cpy->elem[i]
					.mask_cpy.u.ipv4.hdr.dst_ip)[0] & 0xFF);
			break;
		case FLOW_ELEM_TYPE_ETH:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_ETH %i\n", i);
			NT_LOG(DBG, NTCONNECT,
			       "     src mac:  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.s_addr.addr_b[5] & 0xFF);
			NT_LOG(DBG, NTCONNECT,
			       "     dst mac:  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].spec_cpy.u.eth.d_addr.addr_b[5] & 0xFF);
			NT_LOG(DBG, NTCONNECT,
			       "     src mask  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.s_addr.addr_b[5] & 0xFF);
			NT_LOG(DBG, NTCONNECT,
			       "     dst mask  %02X:%02X:%02X:%02X:%02X:%02X\n",
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[0] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[1] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[2] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[3] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[4] & 0xFF,
			       flow_cpy->elem[i].mask_cpy.u.eth.d_addr.addr_b[5] & 0xFF);
			break;
		case FLOW_ELEM_TYPE_VLAN:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_VLAN %i\n", i);
			break;
		case FLOW_ELEM_TYPE_IPV6:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_IPV6 %i\n", i);
			break;
		case FLOW_ELEM_TYPE_SCTP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_SCTP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_TCP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_TCP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_UDP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_UDP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_ICMP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_ICMP %i\n", i);
			break;
		case FLOW_ELEM_TYPE_VXLAN:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_VXLAN %i\n", i);
			break;
		case FLOW_ELEM_TYPE_PORT_ID:
			NT_LOG(DBG, NTCONNECT, "FLOW_ELEM_TYPE_PORT_ID %i\n",
			       i);
			break;
		default:
			NT_LOG(DBG, NTCONNECT, "Unknown item %u\n",
			       flow_cpy->elem[i].type);
			break;
		}
	}

	for (i = 0; i < MAX_FLOW_STREAM_ELEM; i++) {
		uint32_t j;

		if (flow_cpy->action[i].type == FLOW_ACTION_TYPE_END) {
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_END\n");
			break;
		}
		switch (flow_cpy->action[i].type) {
		case FLOW_ACTION_TYPE_RSS:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_RSS %i\n", i);
			NT_LOG(DBG, NTCONNECT, "     queue nb: %u\n",
			       flow_cpy->action[i].conf_cpy.u.rss.rss.queue_num);
			NT_LOG(DBG, NTCONNECT, "     queue:    ");
			for (j = 0;
					j < flow_cpy->action[i]
					.conf_cpy.u.rss.rss.queue_num &&
					j < FLOW_MAX_QUEUES;
					j++) {
				NT_LOG(DBG, NTCONNECT, "%u ",
				       flow_cpy->action[i]
				       .conf_cpy.u.rss.cpy_queue[j]);
			}
			NT_LOG(DBG, NTCONNECT, "\n");
			break;

		case FLOW_ACTION_TYPE_POP_VLAN:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_POP_VLAN %i\n",
			       i);
			break;
		case FLOW_ACTION_TYPE_PUSH_VLAN:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_PUSH_VLAN %i\n", i);
			break;
		case FLOW_ACTION_TYPE_SET_VLAN_VID:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_SET_VLAN_VID %i\n", i);
			break;
		case FLOW_ACTION_TYPE_SET_VLAN_PCP:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_SET_VLAN_PCP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_VXLAN_DECAP:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_VXLAN_DECAP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_VXLAN_ENCAP:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_VXLAN_ENCAP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_DROP:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_DROP %i\n", i);
			break;
		case FLOW_ACTION_TYPE_COUNT:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_COUNT %i\n",
			       i);
			break;
		case FLOW_ACTION_TYPE_MARK:
			NT_LOG(DBG, NTCONNECT, "FLOW_ACTION_TYPE_MARK %i\n", i);
			break;
		case FLOW_ACTION_TYPE_PORT_ID:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_PORT_ID %i: ID=%u\n", i,
			       flow_cpy->action[i].conf_cpy.u.port_id.id);
			break;
		case FLOW_ACTION_TYPE_QUEUE:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_QUEUE %i: queue=%u\n", i,
			       flow_cpy->action[i].conf_cpy.u.queue.index);
			break;
		case FLOW_ACTION_TYPE_SET_TAG:
			NT_LOG(DBG, NTCONNECT,
			       "FLOW_ACTION_TYPE_SET_TAG %i: idx=%u, data=%u, mask=%X\n",
			       i, flow_cpy->action[i].conf_cpy.u.tag.index,
			       flow_cpy->action[i].conf_cpy.u.tag.data,
			       flow_cpy->action[i].conf_cpy.u.tag.mask);
			break;
		default:
			NT_LOG(DBG, NTCONNECT, "Unknown action %u\n",
			       flow_cpy->action[i].type);
			break;
		}
	}
#endif

	/* Call filter with data */
	make_flow_create(FLOW_API_FUNC_VALIDATE, port, flow_cpy, &status,
			 &error);
	return copy_return_status(data, len, status, &error);

	/* Call filter with data */
	make_flow_create(FLOW_API_FUNC_VALIDATE, port, flow_cpy, &status,
			 &error);
	if (!status) {
		*data = malloc(sizeof(struct validate_flow_return_s));
		if (!*data)
			goto validate_flow_error_malloc;
		struct validate_flow_return_s *return_value =
			(struct validate_flow_return_s *)*data;
		*len = sizeof(struct validate_flow_return_s);
		return_value->status = 0;
		return REQUEST_OK;
	}

	*data = malloc(sizeof(struct flow_error_return_s));
	if (!*data)
		goto validate_flow_error_malloc;
	struct flow_error_return_s *return_value =
		(struct flow_error_return_s *)*data;
	*len = sizeof(struct flow_error_return_s);
	return_value->type = error.type;
	strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);
	return_value->status = status;
	return REQUEST_OK;

validate_flow_error_malloc:

	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory %s", __func__);
	return REQUEST_ERR;
}

static int func_flow_query(void *hdl _unused, int client_id _unused,
			   struct ntconn_header_s *hdr, char **data, int *len)
{
	int status;
	struct flow_error error;
	int port = MAX_PORTS;
	struct flow_handle *flow;

	struct query_flow_ntconnect *flow_cpy =
		(struct query_flow_ntconnect *)&(*data)[hdr->len];

	if (hdr->blob_len != sizeof(struct query_flow_ntconnect)) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "Error in filter data");
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_INVALID_REQUEST);
	}

	set_error(&error);

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "%s: [%s:%u] enter\n", __func__, __FILE__, __LINE__);
#endif

	port = flow_cpy->port;

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "Port id=%u\n", port);
#endif

	if (port >= MAX_PORTS) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "port id out of range");
		return ntconn_flow_err_reply_status(data, len,
			NTCONN_FLOW_ERR_INVALID_PORT, ENODEV);
	}

#ifdef DEBUG_FLOW
	NT_LOG(DBG, NTCONNECT, "flow=0x%016llX\n",
	       (unsigned long long)flow_cpy->flow);
#endif

	flow = (struct flow_handle *)flow_cpy->flow;

	const struct flow_action action = {
		flow_cpy->action.type,
		(const void *)&flow_cpy->action.conf_cpy.u.count
	};

	/* Call filter with data */
	void *data_out = NULL;
	uint32_t length = 0;

	status = flow_query(port_eth[port].flw_dev, flow, &action, &data_out,
			    &length, &error);

	*data = malloc(sizeof(struct query_flow_return_s) + length);
	if (*data) {
		struct query_flow_return_s *return_value =
			(struct query_flow_return_s *)*data;
		*len = sizeof(struct query_flow_return_s) + length;

		return_value->status = status;
		return_value->type = error.type;
		strlcpy(return_value->err_msg, error.message, ERR_MSG_LEN);

		if (data_out) {
			memcpy(return_value->data, data_out, length);
			return_value->data_length = length;
			free(data_out);
		} else {
			return_value->data_length = 0;
		}
		return REQUEST_OK;
	}
	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory %s",
	       __func__);
	return REQUEST_ERR;
}

static int flow_request(void *hdl, int client_id _unused,
			struct ntconn_header_s *hdr, char *function,
			char **data, int *len)
{
	return execute_function(this_module_name, hdl, client_id, hdr, function,
				adapter_entry_funcs, data, len, 0);
}

static void flow_free_data(void *hdl _unused, char *data)
{
	if (data)
		free(data);
}

static void flow_client_cleanup(void *hdl _unused, int client_id _unused)
{
	/* Nothing to do */
}

static const ntconnapi_t ntconn_flow_op = { this_module_name,
					    NTCONN_FLOW_VERSION_MAJOR,
					    NTCONN_FLOW_VERSION_MINOR,
					    flow_request,
					    flow_free_data,
					    flow_client_cleanup
					  };

int ntconn_flow_register(struct drv_s *drv)
{
	int i;

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (flow_hdl[i].drv == NULL)
			break;
	}
	if (i == MAX_CLIENTS) {
		NT_LOG(ERR, NTCONNECT,
		       "Cannot register more adapters into NtConnect framework");
		return -1;
	}

	flow_hdl[i].drv = drv;
	return register_ntconn_mod(&drv->p_dev->addr, (void *)&flow_hdl[i],
				   &ntconn_flow_op);
}

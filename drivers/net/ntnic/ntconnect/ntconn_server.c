/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdlib.h>
#include <string.h>

#include "ntconnect.h"
#include "ntconn_mod_helper.h"
#include "nt_util.h"
#include "ntlog.h"

/*
 * Server module always registered on 0000:00:00.0
 */
#define this_module_name "server"

#define NTCONNECT_SERVER_VERSION_MAJOR 0U
#define NTCONNECT_SERVER_VERSION_MINOR 1U

static int func_get_nic_pci(void *hdl, int client_fd,
			    struct ntconn_header_s *hdr, char **data, int *len);
static struct func_s funcs_get_level1[] = {
	{ "nic_pci_ids", NULL, func_get_nic_pci },
	{ NULL, NULL, NULL },
};

/*
 * Entry level
 */
static struct func_s server_entry_funcs[] = {
	{ "get", funcs_get_level1, NULL },
	{ NULL, NULL, NULL },
};

static int func_get_nic_pci(void *hdl, int client_fd _unused,
			    struct ntconn_header_s *hdr _unused, char **data,
			    int *len)
{
	struct ntconn_server_s *serv = (struct ntconn_server_s *)hdl;
	struct ntc_nic_pci_ids_s *npci =
		calloc(1, sizeof(struct ntc_nic_pci_ids_s));
	if (!npci) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}
	int i = 0;

	while (i < MAX_PCI_IDS && serv->pci_id_list[i].pci_id) {
		sprintf(npci->nic_pci_id[i], "%04x:%02x:%02x.%x",
			serv->pci_id_list[i].domain & 0xffff,
			serv->pci_id_list[i].bus, serv->pci_id_list[i].devid,
			serv->pci_id_list[i].function);
		i++;
	}
	npci->num_nics = i;
	*data = (char *)npci;
	*len = sizeof(struct ntc_nic_pci_ids_s);

	return REQUEST_OK;
}

static int ntconn_server_request(void *hdl, int client_id,
				 struct ntconn_header_s *hdr, char *function,
				 char **data, int *len)
{
	return execute_function(this_module_name, hdl, client_id, hdr, function,
				server_entry_funcs, data, len, 0);
}

static void ntconn_server_free_data(void *hdl _unused, char *data)
{
	if (data) {
#ifdef DEBUG
		NT_LOG(DBG, NTCONNECT, "server free data\n");
#endif
		free(data);
	}
}

static const ntconnapi_t ntconn_server_op = { this_module_name,
					      NTCONNECT_SERVER_VERSION_MAJOR,
					      NTCONNECT_SERVER_VERSION_MINOR,
					      ntconn_server_request,
					      ntconn_server_free_data,
					      NULL
					    };

int ntconn_server_register(void *server)
{
	const struct rte_pci_addr addr = {
		.domain = 0, .bus = 0, .devid = 0, .function = 0
	};

	return register_ntconn_mod(&addr, server, &ntconn_server_op);
}

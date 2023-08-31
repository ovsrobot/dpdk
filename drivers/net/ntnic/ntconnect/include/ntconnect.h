/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_H_
#define _NTCONNECT_H_

#include <rte_pci.h>
#include <sched.h>
#include <stdint.h>

#include "ntconnect_api.h"

#define REQUEST_OK 0
#define REQUEST_ERR -1

typedef struct ntconn_api_s {
	/*
	 * Name specifying this module. This name is used in the request string
	 */
	const char *module;
	/*
	 * The version of this module integration
	 */
	uint32_t version_major;
	uint32_t version_minor;
	/*
	 * The request function:
	 * hdl       : pointer to the context of this instance.
	 * client_id : identifying the client. To be able to manage client specific data/state.
	 * function  : pointer to the remainder of the request command (Layer 3). May be modified.
	 *             an example: <pci_id>;adapter;get,interface,port0,link_speed function will
	 *             then be 'get,interface,port0,link_speed'.
	 * hdr       : header for length of command string and length of binary blop.
	 *             The command string will start at "*data" and will have the length hdr->len.
	 *             The binary blob will start at "&(*data)[hdr->len]" and will have the length
	 *             hdr->blob_len.
	 * data      : pointer to the resulting data. Typically this will be allocated.
	 * len       : length of the data in the reply.
	 *
	 * return    : REQUEST_OK on success, REQUEST_ERR on failure. On failure, the data and len
	 *             can contain an describing error text
	 */
	int (*request)(void *hdl, int client_id, struct ntconn_header_s *hdr,
		       char *function, char **data, int *len);
	/*
	 * After each request call, and when 'len' returns > 0, this function is called
	 * after sending reply to client.
	 * hdl       : pointer to the context of this instance.
	 * data      : the data pointer returned in the request function
	 */
	void (*free_data)(void *hdl, char *data);
	/*
	 * Clean up of client specific data allocations. Called when client disconnects from server
	 * hdl       : pointer to the context of this instance.
	 * client_id : identifying the client.
	 */
	void (*client_cleanup)(void *hdl, int client_id);
} ntconnapi_t;

/*
 * ntconn error
 */
typedef struct ntconn_err_s {
	uint32_t err_code;
	const char *err_text;
} ntconn_err_t;

const ntconn_err_t *get_ntconn_error(enum ntconn_err_e err_code);

typedef struct ntconn_mod_s {
	void *hdl;
	struct pci_id_s addr;
	const ntconnapi_t *op;

	pthread_mutex_t mutex;
	struct ntconn_mod_s *next;
} ntconn_mod_t;

struct ntconn_server_s {
	int serv_fd;
	int running;
	/*
	 * list of different pci_ids registered aka SmartNICs
	 */
	struct pci_id_s pci_id_list[MAX_PCI_IDS]; /* 0 - terminates */
	cpu_set_t cpuset;
};

int ntconn_server_register(void *server);

int register_ntconn_mod(const struct rte_pci_addr *addr, void *hdl,
			const ntconnapi_t *op);
int ntconnect_init(const char *sockname, cpu_set_t cpuset);

#endif /* _NTCONNECT_H_ */

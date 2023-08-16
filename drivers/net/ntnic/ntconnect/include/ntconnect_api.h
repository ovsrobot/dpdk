/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_API_H_
#define _NTCONNECT_API_H_

#include "stdint.h"
/*
 * NtConnect API
 */

#define NTCONNECT_SOCKET "/var/run/ntconnect/ntconnect.sock"

enum ntconn_err_e {
	NTCONN_ERR_CODE_NONE = 0U,
	NTCONN_ERR_CODE_INTERNAL_ERROR,
	NTCONN_ERR_CODE_INVALID_REQUEST,
	NTCONN_ERR_CODE_INTERNAL_REPLY_ERROR,
	NTCONN_ERR_CODE_NO_DATA,
	NTCONN_ERR_CODE_NOT_YET_IMPLEMENTED,
	NTCONN_ERR_CODE_MISSING_INVALID_PARAM,
	NTCONN_ERR_CODE_FUNCTION_PARAM_INCOMPLETE,
	NTCONN_ERR_CODE_INTERNAL_FUNC_ERROR,
	NTCONN_ERR_CODE_FUNC_PARAM_NOT_RECOGNIZED,
};

enum ntconn_reply_code_e {
	NTCONN_ADAPTER_ERR_PORT_STATE_FAIL = 0U,
	NTCONN_ADAPTER_ERR_WRONG_LINK_STATE,
	NTCONN_ADAPTER_ERR_TX_POWER_FAIL,
};

enum {
	NTCONN_TAG_NONE,
	NTCONN_TAG_REQUEST,
	NTCONN_TAG_REPLY,
	NTCONN_TAG_ERROR
};

#define MESSAGE_BUFFER 256
#define MAX_ERR_MESSAGE_LENGTH 256

struct reply_err_s {
	enum ntconn_err_e err_code;
	char msg[MAX_ERR_MESSAGE_LENGTH];
};

#define NTCMOD_HDR_LEN sizeof(struct ntconn_header_s)
struct ntconn_header_s {
	uint16_t tag;
	uint16_t len;
	uint32_t blob_len;
};

struct pci_id_s {
	union {
		uint64_t pci_id;
		struct {
			uint32_t domain;
			uint8_t bus;
			uint8_t devid;
			uint8_t function;
			uint8_t pad;
		};
	};
};

#define VERSION_HI(version) ((unsigned int)((version) >> 32))
#define VERSION_LO(version) ((unsigned int)((version) & 0xffffffff))

/*
 * Binary interface description for ntconnect module replies
 */

/*
 * server get,nic_pci_ids
 */
#define MAX_PCI_IDS 16
#define NICS_PCI_ID_LEN 12

struct ntc_nic_pci_ids_s {
	char nic_pci_id[MAX_PCI_IDS][NICS_PCI_ID_LEN + 1];
	int num_nics;
};

#endif /* _NTCONNECT_API_H_ */

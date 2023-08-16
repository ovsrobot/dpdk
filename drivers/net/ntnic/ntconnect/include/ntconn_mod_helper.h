/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONN_MOD_HELPER_H_
#define _NTCONN_MOD_HELPER_H_

#include "ntconnect.h"

/*
 * Module parameter function call tree structures
 */
struct func_s {
	const char *param;
	struct func_s *sub_funcs;
	int (*func)(void *hdl, int client_fd, struct ntconn_header_s *hdr,
		    char **data, int *len);
};

static inline int ntconn_error(char **data, int *len, const char *module,
			       enum ntconn_err_e err_code)
{
	*len = 0;
	if (data) {
		const ntconn_err_t *ntcerr = get_ntconn_error(err_code);
		*data = malloc(4 + strlen(module) + 1 +
			       strlen(ntcerr->err_text) + 1);
		if (*data) {
			sprintf(*data, "----%s:%s", module, ntcerr->err_text);
			*len = strlen(*data) + 1; /* add 0 - terminator */
			*(uint32_t *)*data = (uint32_t)ntcerr->err_code;
		}
	}
	return REQUEST_ERR;
}

static inline int ntconn_reply_status(char **data, int *len,
				      enum ntconn_reply_code_e code)
{
	*len = 0;
	if (data) {
		*data = malloc(sizeof(uint32_t));
		if (*data) {
			*len = sizeof(uint32_t);
			*(uint32_t *)*data = (uint32_t)code;
		}
	}
	return REQUEST_OK;
}

static inline int execute_function(const char *module, void *hdl, int client_id,
				   struct ntconn_header_s *hdr, char *function,
				   struct func_s *func_list, char **data,
				   int *len, int recur_depth)
{
	char *tok = strtok(function, ",");

	if (!tok) {
		if (recur_depth == 0)
			return ntconn_error(data, len, module,
					    NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		else
			return ntconn_error(data, len, module,
					    NTCONN_ERR_CODE_FUNCTION_PARAM_INCOMPLETE);
	}

	hdr->len -= strlen(tok) + 1;
	char *sub_funcs = function + strlen(tok) + 1;
	int idx = 0;

	while (func_list[idx].param) {
		if (strcmp(func_list[idx].param, tok) == 0) {
			/* hit */
			if (func_list[idx].sub_funcs) {
				return execute_function(module, hdl, client_id,
							hdr, sub_funcs,
							func_list[idx].sub_funcs,
							data, len,
							++recur_depth);
			} else if (func_list[idx].func) {
				/* commands/parameters for function in text, zero-terminated */
				*data = sub_funcs;
				return func_list[idx].func(hdl, client_id, hdr,
							   data, len);
			} else {
				return ntconn_error(data, len, module,
						    NTCONN_ERR_CODE_INTERNAL_FUNC_ERROR);
			}
		}
		idx++;
	}
	/* no hits */
	return ntconn_error(data, len, module,
			    NTCONN_ERR_CODE_FUNC_PARAM_NOT_RECOGNIZED);
}

#endif /* _NTCONN_MOD_HELPER_H_ */

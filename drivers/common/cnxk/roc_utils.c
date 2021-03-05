/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

const char *
roc_error_msg_get(int errorcode)
{
	const char *err_msg;

	switch (errorcode) {
	case UTIL_ERR_PARAM:
		err_msg = "Invalid parameter";
		break;
	case UTIL_ERR_FS:
		err_msg = "file operation failed";
		break;
	case UTIL_ERR_INVALID_MODEL:
		err_msg = "Invalid RoC model";
		break;
	default:
		/**
		 * Handle general error (as defined in linux errno.h)
		 */
		if (abs(errorcode) < 300)
			err_msg = strerror(abs(errorcode));
		else
			err_msg = "Unknown error code";
		break;
	}

	return err_msg;
}

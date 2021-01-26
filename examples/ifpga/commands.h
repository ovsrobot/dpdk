/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Intel Corporation
 */

#ifndef _COMMANDS_H_
#define _COMMANDS_H_

#include "opae_api.h"

extern cmdline_parse_ctx_t main_ctx[];

typedef struct {
	char s[38];
} uuid_str;

#endif /* _COMMANDS_H_ */

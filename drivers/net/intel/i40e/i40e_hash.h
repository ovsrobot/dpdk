/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _I40E_HASH_H_
#define _I40E_HASH_H_

#include <rte_ethdev.h>
#include <rte_flow.h>
#include "i40e_ethdev.h"

#ifdef __cplusplus
extern "C" {
#endif

int i40e_hash_filter_create(struct i40e_pf *pf,
			    struct i40e_rte_flow_rss_conf *rss_conf);

int i40e_hash_filter_restore(struct i40e_pf *pf);
int i40e_hash_filter_destroy(struct i40e_pf *pf,
			     const struct i40e_rte_flow_rss_conf *rss_conf);

extern const uint8_t i40e_rss_key_default[I40E_RSS_KEY_LEN];

#ifdef __cplusplus
}
#endif

#endif /* I40E_HASH_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _PDCP_PROCESS_H_
#define _PDCP_PROCESS_H_

#include <rte_pdcp.h>

int
pdcp_process_func_set(struct rte_pdcp_entity *entity, const struct rte_pdcp_entity_conf *conf);

#endif /* _PDCP_PROCESS_H_ */

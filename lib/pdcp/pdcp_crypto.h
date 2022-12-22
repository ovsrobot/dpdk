/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _PDCP_CRYPTO_H_
#define _PDCP_CRYPTO_H_

#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_pdcp.h>

#define PDCP_IV_OFFSET (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define PDCP_IV_LENGTH 16

int pdcp_crypto_sess_create(struct rte_pdcp_entity *entity,
			    const struct rte_pdcp_entity_conf *conf);

int pdcp_crypto_sess_destroy(struct rte_pdcp_entity *entity);

#endif /* _PDCP_CRYPTO_H_ */

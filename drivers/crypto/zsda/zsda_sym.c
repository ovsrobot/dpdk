/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include "cryptodev_pmd.h"

#include "zsda_logs.h"
#include "zsda_sym.h"

int
zsda_encry_match(const void *op_in)
{
	const struct rte_crypto_op *op = op_in;
	struct rte_cryptodev_sym_session *session = op->sym->session;
	struct zsda_sym_session *sess =
		(struct zsda_sym_session *)session->driver_priv_data;

	if (sess->chain_order == ZSDA_SYM_CHAIN_ONLY_CIPHER &&
	    sess->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		return 1;
	else
		return 0;
}

int
zsda_decry_match(const void *op_in)
{
	const struct rte_crypto_op *op = op_in;
	struct rte_cryptodev_sym_session *session = op->sym->session;
	struct zsda_sym_session *sess =
		(struct zsda_sym_session *)session->driver_priv_data;

	if (sess->chain_order == ZSDA_SYM_CHAIN_ONLY_CIPHER &&
	    sess->cipher.op == RTE_CRYPTO_CIPHER_OP_DECRYPT)
		return 1;
	else
		return 0;
}

int
zsda_hash_match(const void *op_in)
{
	const struct rte_crypto_op *op = op_in;
	struct rte_cryptodev_sym_session *session = op->sym->session;
	struct zsda_sym_session *sess =
		(struct zsda_sym_session *)session->driver_priv_data;

	if (sess->chain_order == ZSDA_SYM_CHAIN_ONLY_AUTH)
		return 1;
	else
		return 0;
}

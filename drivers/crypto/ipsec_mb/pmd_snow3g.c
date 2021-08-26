/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2021 Intel Corporation
 */

/**
 * function used to process crypto workload using job API
 */
#include <intel-ipsec-mb.h>

#if defined(RTE_LIB_SECURITY)
#define AESNI_MB_DOCSIS_SEC_ENABLED 1
#include <rte_security.h>
#include <rte_security_driver.h>
#include <rte_ether.h>
#endif

#include "rte_ipsec_mb_pmd_private.h"

#define SNOW3G_IV_LENGTH 16
#define SNOW3G_MAX_BURST 8
#define BYTE_LEN 8
#define SNOW3G_DIGEST_LENGTH 4
#define SNOW3G_MAX_KEY_SIZE  128

uint8_t pmd_driver_id_snow3g;

static const struct rte_cryptodev_capabilities snow3g_capabilities[] = {
	{	/* SNOW 3G (UIA2) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = SNOW3G_DIGEST_LENGTH,
					.max = SNOW3G_DIGEST_LENGTH,
					.increment = 0
				},
				.iv_size = {
					.min = SNOW3G_IV_LENGTH,
					.max = SNOW3G_IV_LENGTH,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* SNOW 3G (UEA2) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.iv_size = {
					.min = SNOW3G_IV_LENGTH,
					.max = SNOW3G_IV_LENGTH,
					.increment = 0
				}
			}, }
		}, }
	},
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

/** SNOW 3G private session structure */
struct snow3g_session {
	enum ipsec_mb_operation op;
	enum rte_crypto_auth_operation auth_op;
	snow3g_key_schedule_t pKeySched_cipher;
	snow3g_key_schedule_t pKeySched_hash;
	uint16_t cipher_iv_offset;
	uint16_t auth_iv_offset;
} __rte_cache_aligned;

struct snow3g_qp_data {
	uint8_t temp_digest[SNOW3G_DIGEST_LENGTH];
	/**< Buffer used to store the digest generated
	 * by the driver when verifying a digest provided
	 * by the user (using authentication verify operation)
	 */
};

/** Parse crypto xform chain and set private session parameters. */
static int
snow3g_session_configure(MB_MGR *mgr, void *priv_sess,
		const struct rte_crypto_sym_xform *xform)
{
	struct snow3g_session *sess = (struct snow3g_session *)priv_sess;
	const struct rte_crypto_sym_xform *auth_xform = NULL;
	const struct rte_crypto_sym_xform *cipher_xform = NULL;
	enum ipsec_mb_operation mode;

	/* Select Crypto operation - hash then cipher / cipher then hash */
	int ret = ipsec_mb_parse_xform(xform, &mode, &auth_xform,
				&cipher_xform, NULL);
	if (ret)
		return ret;

	if (cipher_xform) {
		/* Only SNOW 3G UEA2 supported */
		if (cipher_xform->cipher.algo != RTE_CRYPTO_CIPHER_SNOW3G_UEA2)
			return -ENOTSUP;

		if (cipher_xform->cipher.iv.length != SNOW3G_IV_LENGTH) {
			IPSEC_MB_LOG(ERR, "Wrong IV length");
			return -EINVAL;
		}
		if (cipher_xform->cipher.key.length > SNOW3G_MAX_KEY_SIZE) {
			IPSEC_MB_LOG(ERR, "Not enough memory to store the key");
			return -ENOMEM;
		}

		sess->cipher_iv_offset = cipher_xform->cipher.iv.offset;

		/* Initialize key */
		IMB_SNOW3G_INIT_KEY_SCHED(mgr, cipher_xform->cipher.key.data,
					&sess->pKeySched_cipher);
	}

	if (auth_xform) {
		/* Only SNOW 3G UIA2 supported */
		if (auth_xform->auth.algo != RTE_CRYPTO_AUTH_SNOW3G_UIA2)
			return -ENOTSUP;

		if (auth_xform->auth.digest_length != SNOW3G_DIGEST_LENGTH) {
			IPSEC_MB_LOG(ERR, "Wrong digest length");
			return -EINVAL;
		}
		if (auth_xform->auth.key.length > SNOW3G_MAX_KEY_SIZE) {
			IPSEC_MB_LOG(ERR, "Not enough memory to store the key");
			return -ENOMEM;
		}

		sess->auth_op = auth_xform->auth.op;

		if (auth_xform->auth.iv.length != SNOW3G_IV_LENGTH) {
			IPSEC_MB_LOG(ERR, "Wrong IV length");
			return -EINVAL;
		}
		sess->auth_iv_offset = auth_xform->auth.iv.offset;

		/* Initialize key */
		IMB_SNOW3G_INIT_KEY_SCHED(mgr, auth_xform->auth.key.data,
					&sess->pKeySched_hash);
	}

	sess->op = mode;

	return 0;
}

/** Encrypt/decrypt mbufs with same cipher key. */
static uint8_t
process_snow3g_cipher_op(struct ipsec_mb_qp *qp, struct rte_crypto_op **ops,
		struct snow3g_session *session,
		uint8_t num_ops)
{
	uint32_t i;
	uint8_t processed_ops = 0;
	const void *src[SNOW3G_MAX_BURST];
	void *dst[SNOW3G_MAX_BURST];
	const void *iv[SNOW3G_MAX_BURST];
	uint32_t num_bytes[SNOW3G_MAX_BURST];

	for (i = 0; i < num_ops; i++) {
		src[i] = rte_pktmbuf_mtod(ops[i]->sym->m_src, uint8_t *) +
				(ops[i]->sym->cipher.data.offset >> 3);
		dst[i] = ops[i]->sym->m_dst ?
			rte_pktmbuf_mtod(ops[i]->sym->m_dst, uint8_t *) +
				(ops[i]->sym->cipher.data.offset >> 3) :
			rte_pktmbuf_mtod(ops[i]->sym->m_src, uint8_t *) +
				(ops[i]->sym->cipher.data.offset >> 3);
		iv[i] = rte_crypto_op_ctod_offset(ops[i], uint8_t *,
				session->cipher_iv_offset);
		num_bytes[i] = ops[i]->sym->cipher.data.length >> 3;

		processed_ops++;
	}

	IMB_SNOW3G_F8_N_BUFFER(qp->mb_mgr, &session->pKeySched_cipher, iv,
			src, dst, num_bytes, processed_ops);

	return processed_ops;
}

/** Encrypt/decrypt mbuf (bit level function). */
static uint8_t
process_snow3g_cipher_op_bit(struct ipsec_mb_qp *qp,
		struct rte_crypto_op *op,
		struct snow3g_session *session)
{
	uint8_t *src, *dst;
	uint8_t *iv;
	uint32_t length_in_bits, offset_in_bits;

	offset_in_bits = op->sym->cipher.data.offset;
	src = rte_pktmbuf_mtod(op->sym->m_src, uint8_t *);
	if (op->sym->m_dst == NULL) {
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
		IPSEC_MB_LOG(ERR, "bit-level in-place not supported\n");
		return 0;
	}
	dst = rte_pktmbuf_mtod(op->sym->m_dst, uint8_t *);
	iv = rte_crypto_op_ctod_offset(op, uint8_t *,
				session->cipher_iv_offset);
	length_in_bits = op->sym->cipher.data.length;

	IMB_SNOW3G_F8_1_BUFFER_BIT(qp->mb_mgr, &session->pKeySched_cipher, iv,
			src, dst, length_in_bits, offset_in_bits);

	return 1;
}

/** Generate/verify hash from mbufs with same hash key. */
static int
process_snow3g_hash_op(struct ipsec_mb_qp *qp, struct rte_crypto_op **ops,
		struct snow3g_session *session,
		uint8_t num_ops)
{
	uint32_t i;
	uint8_t processed_ops = 0;
	uint8_t *src, *dst;
	uint32_t length_in_bits;
	uint8_t *iv;
	struct snow3g_qp_data *qp_data = ipsec_mb_get_qp_private_data(qp);

	for (i = 0; i < num_ops; i++) {
		/* Data must be byte aligned */
		if ((ops[i]->sym->auth.data.offset % BYTE_LEN) != 0) {
			ops[i]->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
			IPSEC_MB_LOG(ERR, "Offset");
			break;
		}

		length_in_bits = ops[i]->sym->auth.data.length;

		src = rte_pktmbuf_mtod(ops[i]->sym->m_src, uint8_t *) +
				(ops[i]->sym->auth.data.offset >> 3);
		iv = rte_crypto_op_ctod_offset(ops[i], uint8_t *,
				session->auth_iv_offset);

		if (session->auth_op == RTE_CRYPTO_AUTH_OP_VERIFY) {
			dst = qp_data->temp_digest;

			IMB_SNOW3G_F9_1_BUFFER(qp->mb_mgr,
					&session->pKeySched_hash,
					iv, src, length_in_bits, dst);
			/* Verify digest. */
			if (memcmp(dst, ops[i]->sym->auth.digest.data,
					SNOW3G_DIGEST_LENGTH) != 0)
				ops[i]->status =
					RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
		} else  {
			dst = ops[i]->sym->auth.digest.data;

			IMB_SNOW3G_F9_1_BUFFER(qp->mb_mgr,
					&session->pKeySched_hash,
					iv, src, length_in_bits, dst);
		}
		processed_ops++;
	}

	return processed_ops;
}

/** Process a batch of crypto ops which shares the same session. */
static int
process_ops(struct rte_crypto_op **ops, struct snow3g_session *session,
		struct ipsec_mb_qp *qp, uint8_t num_ops,
		uint16_t *accumulated_enqueued_ops)
{
	uint32_t i;
	uint32_t enqueued_ops, processed_ops;

#ifdef RTE_LIBRTE_PMD_SNOW3G_DEBUG
	for (i = 0; i < num_ops; i++) {
		if (!rte_pktmbuf_is_contiguous(ops[i]->sym->m_src) ||
				(ops[i]->sym->m_dst != NULL &&
				!rte_pktmbuf_is_contiguous(
						ops[i]->sym->m_dst))) {
			IPSEC_MB_LOG(ERR,
				"PMD supports only contiguous mbufs, "
				"op (%p) provides noncontiguous mbuf as "
				"source/destination buffer.\n", ops[i]);
			ops[i]->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
			return 0;
		}
	}
#endif

	switch (session->op) {
	case IPSEC_MB_OP_ENCRYPT_ONLY:
	case IPSEC_MB_OP_DECRYPT_ONLY:
		processed_ops = process_snow3g_cipher_op(qp, ops,
				session, num_ops);
		break;
	case IPSEC_MB_OP_HASH_GEN_ONLY:
	case IPSEC_MB_OP_HASH_VERIFY_ONLY:
		processed_ops = process_snow3g_hash_op(qp, ops, session,
				num_ops);
		break;
	case IPSEC_MB_OP_ENCRYPT_THEN_HASH_GEN:
	case IPSEC_MB_OP_DECRYPT_THEN_HASH_VERIFY:
		processed_ops = process_snow3g_cipher_op(qp, ops, session,
				num_ops);
		process_snow3g_hash_op(qp, ops, session, processed_ops);
		break;
	case IPSEC_MB_OP_HASH_VERIFY_THEN_DECRYPT:
	case IPSEC_MB_OP_HASH_GEN_THEN_ENCRYPT:
		processed_ops = process_snow3g_hash_op(qp, ops, session,
				num_ops);
		process_snow3g_cipher_op(qp, ops, session, processed_ops);
		break;
	default:
		/* Operation not supported. */
		processed_ops = 0;
	}

	for (i = 0; i < num_ops; i++) {
		/*
		 * If there was no error/authentication failure,
		 * change status to successful.
		 */
		if (ops[i]->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED)
			ops[i]->status = RTE_CRYPTO_OP_STATUS_SUCCESS;
		/* Free session if a session-less crypto op. */
		if (ops[i]->sess_type == RTE_CRYPTO_OP_SESSIONLESS) {
			memset(session, 0, sizeof(struct snow3g_session));
			memset(ops[i]->sym->session, 0,
			rte_cryptodev_sym_get_existing_header_session_size(
					ops[i]->sym->session));
			rte_mempool_put(qp->sess_mp_priv, session);
			rte_mempool_put(qp->sess_mp, ops[i]->sym->session);
			ops[i]->sym->session = NULL;
		}
	}

	enqueued_ops = rte_ring_enqueue_burst(qp->ingress_queue,
			(void **)ops, processed_ops, NULL);
	qp->stats.enqueued_count += enqueued_ops;
	*accumulated_enqueued_ops += enqueued_ops;

	return enqueued_ops;
}

/** Process a crypto op with length/offset in bits. */
static int
process_op_bit(struct rte_crypto_op *op, struct snow3g_session *session,
		struct ipsec_mb_qp *qp, uint16_t *accumulated_enqueued_ops)
{
	uint32_t enqueued_op, processed_op;

	switch (session->op) {
	case IPSEC_MB_OP_ENCRYPT_ONLY:
	case IPSEC_MB_OP_DECRYPT_ONLY:

		processed_op = process_snow3g_cipher_op_bit(qp, op,
				session);
		break;
	case IPSEC_MB_OP_HASH_GEN_ONLY:
	case IPSEC_MB_OP_HASH_VERIFY_ONLY:
		processed_op = process_snow3g_hash_op(qp, &op, session, 1);
		break;
	case IPSEC_MB_OP_ENCRYPT_THEN_HASH_GEN:
	case IPSEC_MB_OP_DECRYPT_THEN_HASH_VERIFY:
		processed_op = process_snow3g_cipher_op_bit(qp, op, session);
		if (processed_op == 1)
			process_snow3g_hash_op(qp, &op, session, 1);
		break;
	case IPSEC_MB_OP_HASH_VERIFY_THEN_DECRYPT:
	case IPSEC_MB_OP_HASH_GEN_THEN_ENCRYPT:
		processed_op = process_snow3g_hash_op(qp, &op, session, 1);
		if (processed_op == 1)
			process_snow3g_cipher_op_bit(qp, op, session);
		break;
	default:
		/* Operation not supported. */
		processed_op = 0;
	}

	/*
	 * If there was no error/authentication failure,
	 * change status to successful.
	 */
	if (op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED)
		op->status = RTE_CRYPTO_OP_STATUS_SUCCESS;

	/* Free session if a session-less crypto op. */
	if (op->sess_type == RTE_CRYPTO_OP_SESSIONLESS) {
		memset(op->sym->session, 0, sizeof(struct snow3g_session));
		rte_cryptodev_sym_session_free(op->sym->session);
		op->sym->session = NULL;
	}

	enqueued_op = rte_ring_enqueue_burst(qp->ingress_queue,
			(void **)&op, processed_op, NULL);
	qp->stats.enqueued_count += enqueued_op;
	*accumulated_enqueued_ops += enqueued_op;

	return enqueued_op;
}

static uint16_t
snow3g_pmd_dequeue_burst(void *queue_pair,
		struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct ipsec_mb_qp *qp = queue_pair;
	struct rte_crypto_op *c_ops[SNOW3G_MAX_BURST];
	struct rte_crypto_op *curr_c_op;

	struct snow3g_session *prev_sess = NULL, *curr_sess = NULL;
	uint32_t i;
	uint8_t burst_size = 0;
	uint16_t enqueued_ops = 0;
	uint8_t processed_ops;


	uint32_t nb_dequeued;

	nb_dequeued = rte_ring_dequeue_burst(qp->ingress_queue,
			(void **)ops, nb_ops, NULL);




	for (i = 0; i < nb_dequeued; i++) {
		curr_c_op = ops[i];

		/* Set status as enqueued (not processed yet) by default. */
		curr_c_op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

		curr_sess = ipsec_mb_get_session_private(qp, curr_c_op);
		if (unlikely(curr_sess == NULL ||
				curr_sess->op == IPSEC_MB_OP_NOT_SUPPORTED)) {
			curr_c_op->status =
					RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
			break;
		}

		/* If length/offset is at bit-level,
		 * process this buffer alone.
		 */
		if (((curr_c_op->sym->cipher.data.length % BYTE_LEN) != 0)
				|| ((curr_c_op->sym->cipher.data.offset
					% BYTE_LEN) != 0)) {
			/* Process the ops of the previous session. */
			if (prev_sess != NULL) {
				processed_ops = process_ops(c_ops, prev_sess,
				qp, burst_size, &enqueued_ops);
				if (processed_ops < burst_size) {
					burst_size = 0;
					break;
				}

				burst_size = 0;
				prev_sess = NULL;
			}

			processed_ops = process_op_bit(curr_c_op, curr_sess,
							qp, &enqueued_ops);
			if (processed_ops != 1)
				break;

			continue;
		}

		/* Batch ops that share the same session. */
		if (prev_sess == NULL) {
			prev_sess = curr_sess;
			c_ops[burst_size++] = curr_c_op;
		} else if (curr_sess == prev_sess) {
			c_ops[burst_size++] = curr_c_op;
			/*
			 * When there are enough ops to process in a batch,
			 * process them, and start a new batch.
			 */
			if (burst_size == SNOW3G_MAX_BURST) {
				processed_ops = process_ops(c_ops, prev_sess,
						qp, burst_size, &enqueued_ops);
				if (processed_ops < burst_size) {
					burst_size = 0;
					break;
				}

				burst_size = 0;
				prev_sess = NULL;
			}
		} else {
			/*
			 * Different session, process the ops
			 * of the previous session.
			 */
			processed_ops = process_ops(c_ops, prev_sess,
					qp, burst_size, &enqueued_ops);
			if (processed_ops < burst_size) {
				burst_size = 0;
				break;
			}

			burst_size = 0;
			prev_sess = curr_sess;

			c_ops[burst_size++] = curr_c_op;
		}
	}

	if (burst_size != 0) {
		/* Process the crypto ops of the last session. */
		processed_ops = process_ops(c_ops, prev_sess,
				qp, burst_size, &enqueued_ops);
	}



	qp->stats.dequeued_count += i;

	return i;
}

struct rte_cryptodev_ops snow3g_pmd_ops = {
	.dev_configure = ipsec_mb_pmd_config,
	.dev_start = ipsec_mb_pmd_start,
	.dev_stop = ipsec_mb_pmd_stop,
	.dev_close = ipsec_mb_pmd_close,

	.stats_get = ipsec_mb_pmd_stats_get,
	.stats_reset = ipsec_mb_pmd_stats_reset,

	.dev_infos_get = ipsec_mb_pmd_info_get,

	.queue_pair_setup = ipsec_mb_pmd_qp_setup,
	.queue_pair_release = ipsec_mb_pmd_qp_release,

	.sym_session_get_size = ipsec_mb_pmd_sym_session_get_size,
	.sym_session_configure = ipsec_mb_pmd_sym_session_configure,
	.sym_session_clear = ipsec_mb_pmd_sym_session_clear
};

struct rte_cryptodev_ops *rte_snow3g_pmd_ops = &snow3g_pmd_ops;

static int
cryptodev_snow3g_probe(struct rte_vdev_device *vdev)
{
	return cryptodev_ipsec_mb_create(vdev, IPSEC_MB_PMD_TYPE_SNOW3G);
}

static struct rte_vdev_driver cryptodev_snow3g_pmd_drv = {
	.probe = cryptodev_snow3g_probe,
	.remove = cryptodev_ipsec_mb_remove
};

static struct cryptodev_driver snow3g_crypto_drv;

RTE_PMD_REGISTER_VDEV(CRYPTODEV_NAME_SNOW3G_PMD, cryptodev_snow3g_pmd_drv);
RTE_PMD_REGISTER_ALIAS(CRYPTODEV_NAME_SNOW3G_PMD, cryptodev_snow3g_pmd);
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_SNOW3G_PMD,
			       "max_nb_queue_pairs=<int> socket_id=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(snow3g_crypto_drv,
				cryptodev_snow3g_pmd_drv.driver,
				pmd_driver_id_snow3g);

/* Constructor function to register snow3g PMD */
RTE_INIT(ipsec_mb_register_snow3g)
{
	struct ipsec_mb_pmd_data *snow3g_data
		= &ipsec_mb_pmds[IPSEC_MB_PMD_TYPE_SNOW3G];

	snow3g_data->caps = snow3g_capabilities;
	snow3g_data->dequeue_burst = snow3g_pmd_dequeue_burst;
	snow3g_data->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_NON_BYTE_ALIGNED_DATA |
			RTE_CRYPTODEV_FF_SYM_SESSIONLESS |
			RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT;
	snow3g_data->internals_priv_size = 0;
	snow3g_data->ops = &snow3g_pmd_ops;
	snow3g_data->qp_priv_size = sizeof(struct snow3g_qp_data);
	snow3g_data->session_configure = snow3g_session_configure;
	snow3g_data->session_priv_size = sizeof(struct snow3g_session);
}

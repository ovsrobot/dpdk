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

#define ZUC_IV_KEY_LENGTH 16
#define ZUC_DIGEST_LENGTH 4
#define ZUC_MAX_BURST 16
#define BYTE_LEN 8

uint8_t pmd_driver_id_zuc;

static const struct rte_cryptodev_capabilities zuc_capabilities[] = {
	{	/* ZUC (EIA3) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_ZUC_EIA3,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = ZUC_DIGEST_LENGTH,
					.max = ZUC_DIGEST_LENGTH,
					.increment = 0
				},
				.iv_size = {
					.min = ZUC_IV_KEY_LENGTH,
					.max = ZUC_IV_KEY_LENGTH,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* ZUC (EEA3) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_ZUC_EEA3,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.iv_size = {
					.min = ZUC_IV_KEY_LENGTH,
					.max = ZUC_IV_KEY_LENGTH,
					.increment = 0
				},
			}, }
		}, }
	},
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

/** ZUC private session structure */
struct zuc_session {
	enum ipsec_mb_operation op;
	enum rte_crypto_auth_operation auth_op;
	uint8_t pKey_cipher[ZUC_IV_KEY_LENGTH];
	uint8_t pKey_hash[ZUC_IV_KEY_LENGTH];
	uint16_t cipher_iv_offset;
	uint16_t auth_iv_offset;
} __rte_cache_aligned;

struct zuc_qp_data {

	uint8_t temp_digest[ZUC_DIGEST_LENGTH];
	/* *< Buffers used to store the digest generated
	 * by the driver when verifying a digest provided
	 * by the user (using authentication verify operation)
	 */
};

/** Parse crypto xform chain and set private session parameters. */
static int
zuc_session_configure(__rte_unused IMB_MGR * mgr, void *zuc_sess,
		const struct rte_crypto_sym_xform *xform)
{
	struct zuc_session *sess = (struct zuc_session *) zuc_sess;
	const struct rte_crypto_sym_xform *auth_xform = NULL;
	const struct rte_crypto_sym_xform *cipher_xform = NULL;
	enum ipsec_mb_operation mode;
	/* Select Crypto operation - hash then cipher / cipher then hash */
	int ret = ipsec_mb_parse_xform(xform, &mode, &auth_xform,
				&cipher_xform, NULL);

	if (ret)
		return ret;

	if (cipher_xform) {
		/* Only ZUC EEA3 supported */
		if (cipher_xform->cipher.algo != RTE_CRYPTO_CIPHER_ZUC_EEA3)
			return -ENOTSUP;

		if (cipher_xform->cipher.iv.length != ZUC_IV_KEY_LENGTH) {
			IPSEC_MB_LOG(ERR, "Wrong IV length");
			return -EINVAL;
		}
		sess->cipher_iv_offset = cipher_xform->cipher.iv.offset;

		/* Copy the key */
		memcpy(sess->pKey_cipher, cipher_xform->cipher.key.data,
				ZUC_IV_KEY_LENGTH);
	}

	if (auth_xform) {
		/* Only ZUC EIA3 supported */
		if (auth_xform->auth.algo != RTE_CRYPTO_AUTH_ZUC_EIA3)
			return -ENOTSUP;

		if (auth_xform->auth.digest_length != ZUC_DIGEST_LENGTH) {
			IPSEC_MB_LOG(ERR, "Wrong digest length");
			return -EINVAL;
		}

		sess->auth_op = auth_xform->auth.op;

		if (auth_xform->auth.iv.length != ZUC_IV_KEY_LENGTH) {
			IPSEC_MB_LOG(ERR, "Wrong IV length");
			return -EINVAL;
		}
		sess->auth_iv_offset = auth_xform->auth.iv.offset;

		/* Copy the key */
		memcpy(sess->pKey_hash, auth_xform->auth.key.data,
				ZUC_IV_KEY_LENGTH);
	}

	sess->op = mode;
	return 0;
}

/** Encrypt/decrypt mbufs. */
static uint8_t
process_zuc_cipher_op(struct ipsec_mb_qp *qp, struct rte_crypto_op **ops,
		struct zuc_session **sessions,
		uint8_t num_ops)
{
	unsigned int i;
	uint8_t processed_ops = 0;
	const void *src[ZUC_MAX_BURST];
	void *dst[ZUC_MAX_BURST];
	const void *iv[ZUC_MAX_BURST];
	uint32_t num_bytes[ZUC_MAX_BURST];
	const void *cipher_keys[ZUC_MAX_BURST];
	struct zuc_session *sess;

	for (i = 0; i < num_ops; i++) {
		if (((ops[i]->sym->cipher.data.length % BYTE_LEN) != 0)
				|| ((ops[i]->sym->cipher.data.offset
					% BYTE_LEN) != 0)) {
			ops[i]->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
			IPSEC_MB_LOG(ERR, "Data Length or offset");
			break;
		}

		sess = sessions[i];

#ifdef RTE_LIBRTE_PMD_ZUC_DEBUG
		if (!rte_pktmbuf_is_contiguous(ops[i]->sym->m_src) ||
				(ops[i]->sym->m_dst != NULL &&
				!rte_pktmbuf_is_contiguous(
						ops[i]->sym->m_dst))) {
			IPSEC_MB_LOG(ERR, "PMD supports only "
				" contiguous mbufs, op (%p) "
				"provides noncontiguous mbuf "
				"as source/destination buffer.\n",
				"PMD supports only contiguous mbufs, "
				"op (%p) provides noncontiguous mbuf "
				"as source/destination buffer.\n",
				ops[i]);
			ops[i]->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
			break;
		}
#endif

		src[i] = rte_pktmbuf_mtod(ops[i]->sym->m_src, uint8_t *) +
				(ops[i]->sym->cipher.data.offset >> 3);
		dst[i] = ops[i]->sym->m_dst ?
			rte_pktmbuf_mtod(ops[i]->sym->m_dst, uint8_t *) +
				(ops[i]->sym->cipher.data.offset >> 3) :
			rte_pktmbuf_mtod(ops[i]->sym->m_src, uint8_t *) +
				(ops[i]->sym->cipher.data.offset >> 3);
		iv[i] = rte_crypto_op_ctod_offset(ops[i], uint8_t *,
				sess->cipher_iv_offset);
		num_bytes[i] = ops[i]->sym->cipher.data.length >> 3;

		cipher_keys[i] = sess->pKey_cipher;

		processed_ops++;
	}

	IMB_ZUC_EEA3_N_BUFFER(qp->mb_mgr, (const void **)cipher_keys,
			(const void **)iv, (const void **)src, (void **)dst,
			num_bytes, processed_ops);

	return processed_ops;
}

/** Generate/verify hash from mbufs. */
static int
process_zuc_hash_op(struct ipsec_mb_qp *qp, struct rte_crypto_op **ops,
		struct zuc_session **sessions,
		uint8_t num_ops)
{
	unsigned int i;
	uint8_t processed_ops = 0;
	uint8_t *src[ZUC_MAX_BURST];
	uint32_t *dst[ZUC_MAX_BURST];
	uint32_t length_in_bits[ZUC_MAX_BURST];
	uint8_t *iv[ZUC_MAX_BURST];
	const void *hash_keys[ZUC_MAX_BURST];
	struct zuc_session *sess;
	struct zuc_qp_data *qp_data = ipsec_mb_get_qp_private_data(qp);


	for (i = 0; i < num_ops; i++) {
		/* Data must be byte aligned */
		if ((ops[i]->sym->auth.data.offset % BYTE_LEN) != 0) {
			ops[i]->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
			IPSEC_MB_LOG(ERR, "Offset");
			break;
		}

		sess = sessions[i];

		length_in_bits[i] = ops[i]->sym->auth.data.length;

		src[i] = rte_pktmbuf_mtod(ops[i]->sym->m_src, uint8_t *) +
				(ops[i]->sym->auth.data.offset >> 3);
		iv[i] = rte_crypto_op_ctod_offset(ops[i], uint8_t *,
				sess->auth_iv_offset);

		hash_keys[i] = sess->pKey_hash;
		if (sess->auth_op == RTE_CRYPTO_AUTH_OP_VERIFY)
			dst[i] = (uint32_t *)qp_data->temp_digest;
		else
			dst[i] = (uint32_t *)ops[i]->sym->auth.digest.data;

		processed_ops++;
	}

	IMB_ZUC_EIA3_N_BUFFER(qp->mb_mgr, (const void **)hash_keys,
			(const void * const *)iv, (const void * const *)src,
			length_in_bits, dst, processed_ops);

	/*
	 * If tag needs to be verified, compare generated tag
	 * with attached tag
	 */
	for (i = 0; i < processed_ops; i++)
		if (sessions[i]->auth_op == RTE_CRYPTO_AUTH_OP_VERIFY)
			if (memcmp(dst[i], ops[i]->sym->auth.digest.data,
					ZUC_DIGEST_LENGTH) != 0)
				ops[i]->status =
					RTE_CRYPTO_OP_STATUS_AUTH_FAILED;

	return processed_ops;
}

/** Process a batch of crypto ops which shares the same operation type. */
static int
process_ops(struct rte_crypto_op **ops, enum ipsec_mb_operation op_type,
		struct zuc_session **sessions,
		struct ipsec_mb_qp *qp, uint8_t num_ops,
		uint16_t *accumulated_enqueued_ops)
{
	unsigned int i;
	unsigned int processed_ops;

	switch (op_type) {
	case IPSEC_MB_OP_ENCRYPT_ONLY:
	case IPSEC_MB_OP_DECRYPT_ONLY:
		processed_ops = process_zuc_cipher_op(qp, ops,
				sessions, num_ops);
		break;
	case IPSEC_MB_OP_HASH_GEN_ONLY:
	case IPSEC_MB_OP_HASH_VERIFY_ONLY:
		processed_ops = process_zuc_hash_op(qp, ops, sessions,
				num_ops);
		break;
	case IPSEC_MB_OP_ENCRYPT_THEN_HASH_GEN:
		processed_ops = process_zuc_cipher_op(qp, ops, sessions,
				num_ops);
		process_zuc_hash_op(qp, ops, sessions, processed_ops);
		break;
	case IPSEC_MB_OP_HASH_VERIFY_THEN_DECRYPT:
		processed_ops = process_zuc_hash_op(qp, ops, sessions,
				num_ops);
		process_zuc_cipher_op(qp, ops, sessions, processed_ops);
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
			memset(sessions[i], 0, sizeof(struct zuc_session));
			memset(ops[i]->sym->session, 0,
			rte_cryptodev_sym_get_existing_header_session_size(
					ops[i]->sym->session));
			rte_mempool_put(qp->sess_mp_priv, sessions[i]);
			rte_mempool_put(qp->sess_mp, ops[i]->sym->session);
			ops[i]->sym->session = NULL;
		}
	}

	*accumulated_enqueued_ops += processed_ops;

	return processed_ops;
}

static uint16_t
zuc_pmd_dequeue_burst(void *queue_pair,
		struct rte_crypto_op **c_ops, uint16_t nb_ops)
{

	struct rte_crypto_op *curr_c_op;

	struct zuc_session *curr_sess;
	struct zuc_session *sessions[ZUC_MAX_BURST];
	enum ipsec_mb_operation prev_zuc_op = IPSEC_MB_OP_NOT_SUPPORTED;
	enum ipsec_mb_operation curr_zuc_op;
	struct ipsec_mb_qp *qp = queue_pair;
	unsigned int nb_dequeued;
	unsigned int i;
	uint8_t burst_size = 0;
	uint16_t enqueued_ops = 0;
	uint8_t processed_ops;

	nb_dequeued = rte_ring_dequeue_burst(qp->ingress_queue,
			(void **)c_ops, nb_ops, NULL);


	for (i = 0; i < nb_dequeued; i++) {
		curr_c_op = c_ops[i];

		curr_sess = (struct zuc_session *)
			ipsec_mb_get_session_private(qp, curr_c_op);
		if (unlikely(curr_sess == NULL)) {
			curr_c_op->status =
					RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
			break;
		}

		curr_zuc_op = curr_sess->op;

		/*
		 * Batch ops that share the same operation type
		 * (cipher only, auth only...).
		 */
		if (burst_size == 0) {
			prev_zuc_op = curr_zuc_op;
			c_ops[0] = curr_c_op;
			sessions[0] = curr_sess;
			burst_size++;
		} else if (curr_zuc_op == prev_zuc_op) {
			c_ops[burst_size] = curr_c_op;
			sessions[burst_size] = curr_sess;
			burst_size++;
			/*
			 * When there are enough ops to process in a batch,
			 * process them, and start a new batch.
			 */
			if (burst_size == ZUC_MAX_BURST) {
				processed_ops = process_ops(c_ops, curr_zuc_op,
						sessions, qp, burst_size,
						&enqueued_ops);
				if (processed_ops < burst_size) {
					burst_size = 0;
					break;
				}

				burst_size = 0;
			}
		} else {
			/*
			 * Different operation type, process the ops
			 * of the previous type.
			 */
			processed_ops = process_ops(c_ops, prev_zuc_op,
					sessions, qp, burst_size,
					&enqueued_ops);
			if (processed_ops < burst_size) {
				burst_size = 0;
				break;
			}

			burst_size = 0;
			prev_zuc_op = curr_zuc_op;

			c_ops[0] = curr_c_op;
			sessions[0] = curr_sess;
			burst_size++;
		}
	}

	if (burst_size != 0) {
		/* Process the crypto ops of the last operation type. */
		processed_ops = process_ops(c_ops, prev_zuc_op,
				sessions, qp, burst_size,
				&enqueued_ops);
	}


	qp->stats.dequeued_count += i;
	return i;
}

struct rte_cryptodev_ops zuc_pmd_ops = {
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

struct rte_cryptodev_ops *rte_zuc_pmd_ops = &zuc_pmd_ops;

static int
cryptodev_zuc_probe(struct rte_vdev_device *vdev)
{
	return cryptodev_ipsec_mb_create(vdev, IPSEC_MB_PMD_TYPE_ZUC);
}

static struct rte_vdev_driver cryptodev_zuc_pmd_drv = {
	.probe = cryptodev_zuc_probe,
	.remove = cryptodev_ipsec_mb_remove

};

static struct cryptodev_driver zuc_crypto_drv;

RTE_PMD_REGISTER_VDEV(CRYPTODEV_NAME_ZUC_PMD, cryptodev_zuc_pmd_drv);
RTE_PMD_REGISTER_ALIAS(CRYPTODEV_NAME_ZUC_PMD, cryptodev_zuc_pmd);
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_ZUC_PMD,
	"max_nb_queue_pairs=<int> socket_id=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(zuc_crypto_drv, cryptodev_zuc_pmd_drv.driver,
		pmd_driver_id_zuc);

/* Constructor function to register zuc PMD */
RTE_INIT(ipsec_mb_register_zuc)
{
	struct ipsec_mb_pmd_data *zuc_data
	    = &ipsec_mb_pmds[IPSEC_MB_PMD_TYPE_ZUC];

	zuc_data->caps = zuc_capabilities;
	zuc_data->dequeue_burst = zuc_pmd_dequeue_burst;
	zuc_data->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO
			| RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING
			| RTE_CRYPTODEV_FF_NON_BYTE_ALIGNED_DATA
			| RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT
			| RTE_CRYPTODEV_FF_SYM_SESSIONLESS
			| RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT;
	zuc_data->internals_priv_size = 0;
	zuc_data->ops = &zuc_pmd_ops;
	zuc_data->qp_priv_size = sizeof(struct zuc_qp_data);
	zuc_data->session_configure = zuc_session_configure;
	zuc_data->session_priv_size = sizeof(struct zuc_session);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_cryptodev_pmd.h>

#include "adf_transport_access_macros.h"
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"

#include "qat_sym.h"
#include "qat_sym_pmd.h"
#include "qat_sym_session.h"
#include "qat_qp.h"

static __rte_always_inline int32_t
qat_sym_dp_fill_sgl(struct qat_qp *qp, struct icp_qat_fw_la_bulk_req *req,
		struct rte_crypto_sgl *sgl)
{
	struct qat_queue *tx_queue = &qp->tx_q;
	struct qat_sym_op_cookie *cookie;
	struct qat_sgl *list;
	uint32_t i;
	uint32_t total_len = 0;

	if (!sgl)
		return -EINVAL;
	if (sgl->num < 2 || sgl->num > QAT_SYM_SGL_MAX_NUMBER || !sgl->vec)
		return -EINVAL;

	ICP_QAT_FW_COMN_PTR_TYPE_SET(req->comn_hdr.comn_req_flags,
			QAT_COMN_PTR_TYPE_SGL);
	cookie = qp->op_cookies[tx_queue->tail >> tx_queue->trailz];
	list = (struct qat_sgl *)&cookie->qat_sgl_src;

	for (i = 0; i < sgl->num; i++) {
		list->buffers[i].len = sgl->vec[i].len;
		list->buffers[i].resrvd = 0;
		list->buffers[i].addr = sgl->vec[i].iova;
		if (total_len + sgl->vec[i].len > UINT32_MAX) {
			QAT_DP_LOG(ERR, "Message too long");
			return -ENOMEM;
		}
		total_len += sgl->vec[i].len;
	}

	list->num_bufs = i;
	req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			cookie->qat_sgl_src_phys_addr;
	req->comn_mid.src_length = req->comn_mid.dst_length = 0;
	return total_len;
}

static __rte_always_inline void
set_cipher_iv(struct icp_qat_fw_la_cipher_req_params *cipher_param,
		struct rte_crypto_vec *iv, uint32_t iv_len,
		struct icp_qat_fw_la_bulk_req *qat_req)
{
	/* copy IV into request if it fits */
	if (iv_len <= sizeof(cipher_param->u.cipher_IV_array))
		rte_memcpy(cipher_param->u.cipher_IV_array, iv->base, iv_len);
	else {
		ICP_QAT_FW_LA_CIPH_IV_FLD_FLAG_SET(
				qat_req->comn_hdr.serv_specif_flags,
				ICP_QAT_FW_CIPH_IV_64BIT_PTR);
		cipher_param->u.s.cipher_IV_ptr = iv->iova;
	}
}

#define QAT_SYM_DP_IS_RESP_SUCCESS(resp) \
	(ICP_QAT_FW_COMN_STATUS_FLAG_OK == \
	ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(resp->comn_hdr.comn_status))

#define QAT_SYM_DP_IS_VEC_VALID(qp, flag, n) \
	(((qp)->service_type == QAT_SERVICE_SYMMETRIC) && \
	(flags & RTE_CRYPTO_HW_DP_FF_SESSIONLESS) == 0 && \
	(flags & RTE_CRYPTO_HW_DP_FF_SECURITY_SESSION) == 0 && \
	((qp)->enqueued + (qp)->cached + (n) < qp->nb_descriptors - 1))

static __rte_always_inline void
qat_sym_dp_update_tx_queue(struct qat_qp *qp, struct qat_queue *tx_queue,
		uint32_t tail, uint32_t n, uint32_t flags)
{
	if (unlikely((flags & RTE_CRYPTO_HW_DP_FF_KICK_QUEUE) ||
			qp->cached + n > QAT_CSR_HEAD_WRITE_THRESH)) {
		qp->enqueued += n;
		qp->stats.enqueued_count += n;

		tx_queue->tail = tail;

		WRITE_CSR_RING_TAIL(qp->mmap_bar_addr,
				tx_queue->hw_bundle_number,
				tx_queue->hw_queue_number, tx_queue->tail);
		tx_queue->csr_tail = tx_queue->tail;
		qp->cached = 0;

		return;
	}

	qp->cached += n;
}

static __rte_always_inline void
qat_sym_dp_fill_vec_status(int32_t *sta, int status, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		sta[i] = status;
}

static __rte_always_inline uint32_t
qat_sym_dp_enqueue_aead(struct rte_cryptodev *dev, uint16_t qp_id,
	union rte_cryptodev_hw_session_ctx session,
	union rte_crypto_sym_ofs ofs, struct rte_crypto_sym_vec *vec,
	void **opaque, uint32_t flags)
{
	struct qat_qp *qp = dev->data->queue_pairs[qp_id];
	struct rte_cryptodev_sym_session *sess;
	struct qat_queue *tx_queue;
	struct qat_sym_session *ctx;
	uint32_t i;
	register uint32_t tail;

	if (unlikely(QAT_SYM_DP_IS_VEC_VALID(qp, flags, vec->num) == 0)) {
		QAT_DP_LOG(ERR, "Operation not supported");
		qat_sym_dp_fill_vec_status(vec->status, -1, vec->num);
		return 0;
	}

	sess = session.crypto_sess;
	ctx = (struct qat_sym_session *)get_sym_session_private_data(sess,
			dev->driver_id);
	tx_queue = &qp->tx_q;
	tail = (tx_queue->tail + qp->cached * tx_queue->msg_size) &
			tx_queue->modulo_mask;

	for (i = 0; i < vec->num; i++) {
		struct icp_qat_fw_la_bulk_req *req;
		struct icp_qat_fw_la_cipher_req_params *cipher_param;
		struct icp_qat_fw_la_auth_req_params *auth_param;
		struct rte_crypto_sgl *sgl = &vec->sgl[i];
		struct rte_crypto_vec *iv_vec = &vec->iv_vec[i];
		struct rte_crypto_vec *aad_vec = &vec->aad_vec[i];
		struct rte_crypto_vec *digest_vec = &vec->digest_vec[i];
		uint8_t *aad_data;
		uint8_t aad_ccm_real_len;
		uint8_t aad_len_field_sz;
		uint32_t aead_len, msg_len_be;
		rte_iova_t aad_iova = 0;
		uint8_t q;

		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + tail);
		rte_mov128((uint8_t *)req,
			(const uint8_t *)&(ctx->fw_req));

		if (i == 0 || (flags & RTE_CRYPTO_HW_DP_FF_SET_OPAQUE_ARRAY))
			req->comn_mid.opaque_data = (uint64_t)opaque[i];

		cipher_param = (void *)&req->serv_specif_rqpars;
		auth_param = (void *)((uint8_t *)cipher_param +
				ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
		req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			sgl->vec[0].iova;
		req->comn_mid.src_length = req->comn_mid.dst_length =
			sgl->vec[0].len;

		aead_len = sgl->vec[0].len - ofs.ofs.cipher.head -
				ofs.ofs.cipher.tail;

		switch (ctx->qat_hash_alg) {
		case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
		case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
			ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
				req->comn_hdr.serv_specif_flags,
					ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
			rte_memcpy_generic(cipher_param->u.cipher_IV_array,
					iv_vec->base, ctx->cipher_iv.length);
			aad_iova = aad_vec->iova;
			break;
		case ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC:
			aad_data = aad_vec->base;
			aad_iova = aad_vec->iova;
			aad_ccm_real_len = 0;
			aad_len_field_sz = 0;
			msg_len_be = rte_bswap32(aead_len);

			if (ctx->aad_len > ICP_QAT_HW_CCM_AAD_DATA_OFFSET) {
				aad_len_field_sz = ICP_QAT_HW_CCM_AAD_LEN_INFO;
				aad_ccm_real_len = ctx->aad_len -
					ICP_QAT_HW_CCM_AAD_B0_LEN -
					ICP_QAT_HW_CCM_AAD_LEN_INFO;
			} else {
				aad_data = iv_vec->base;
				aad_iova = iv_vec->iova;
			}

			q = ICP_QAT_HW_CCM_NQ_CONST - ctx->cipher_iv.length;
			aad_data[0] = ICP_QAT_HW_CCM_BUILD_B0_FLAGS(
				aad_len_field_sz, ctx->digest_length, q);
			if (q > ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE) {
				memcpy(aad_data	+ ctx->cipher_iv.length +
					ICP_QAT_HW_CCM_NONCE_OFFSET + (q -
					ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE),
					(uint8_t *)&msg_len_be,
					ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE);
			} else {
				memcpy(aad_data	+ ctx->cipher_iv.length +
					ICP_QAT_HW_CCM_NONCE_OFFSET,
					(uint8_t *)&msg_len_be +
					(ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE
					- q), q);
			}

			if (aad_len_field_sz > 0) {
				*(uint16_t *)
					&aad_data[ICP_QAT_HW_CCM_AAD_B0_LEN] =
						rte_bswap16(aad_ccm_real_len);

				if ((aad_ccm_real_len + aad_len_field_sz)
					% ICP_QAT_HW_CCM_AAD_B0_LEN) {
					uint8_t pad_len = 0;
					uint8_t pad_idx = 0;

					pad_len = ICP_QAT_HW_CCM_AAD_B0_LEN -
						((aad_ccm_real_len +
						aad_len_field_sz) %
						ICP_QAT_HW_CCM_AAD_B0_LEN);
					pad_idx = ICP_QAT_HW_CCM_AAD_B0_LEN +
						aad_ccm_real_len +
						aad_len_field_sz;
					memset(&aad_data[pad_idx], 0, pad_len);
				}

				rte_memcpy(((uint8_t *)cipher_param->
					u.cipher_IV_array) +
					ICP_QAT_HW_CCM_NONCE_OFFSET,
					(uint8_t *)iv_vec->base +
					ICP_QAT_HW_CCM_NONCE_OFFSET,
					ctx->cipher_iv.length);
				*(uint8_t *)&cipher_param->
					u.cipher_IV_array[0] =
					q - ICP_QAT_HW_CCM_NONCE_OFFSET;

				rte_memcpy((uint8_t *)aad_vec->base +
					ICP_QAT_HW_CCM_NONCE_OFFSET,
					(uint8_t *)iv_vec->base +
					ICP_QAT_HW_CCM_NONCE_OFFSET,
					ctx->cipher_iv.length);
			}
			break;
		default:
			if (flags & RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
				break;
			/* Give up enqueue if exhaust enqueue is not set */
			QAT_DP_LOG(ERR, "Operation not supported");
			qat_sym_dp_fill_vec_status(vec->status, -1, vec->num);
			return 0;
		}

		cipher_param->cipher_offset = ofs.ofs.cipher.head;
		cipher_param->cipher_length = aead_len;
		auth_param->auth_off = ofs.ofs.cipher.head;
		auth_param->auth_len = aead_len;
		auth_param->auth_res_addr = digest_vec->iova;
		auth_param->u1.aad_adr = aad_iova;

		/* SGL processing */
		if (unlikely(sgl->num > 1)) {
			int total_len = qat_sym_dp_fill_sgl(qp, req, sgl);

			if (total_len < 0) {
				if (flags & RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
					break;
				/* Give up enqueue if exhaust is not set */
				QAT_DP_LOG(ERR, "Operation not supported");
				qat_sym_dp_fill_vec_status(vec->status, -1,
						vec->num);
				return 0;
			}

			cipher_param->cipher_length = auth_param->auth_len =
				total_len - ofs.ofs.cipher.head -
				ofs.ofs.cipher.tail;
		}

		if (ctx->is_single_pass) {
			cipher_param->spc_aad_addr = aad_iova;
			cipher_param->spc_auth_res_addr = digest_vec->iova;
		}

		tail = (tail + tx_queue->msg_size) & tx_queue->modulo_mask;


	}

	if (unlikely(i < vec->num))
		qat_sym_dp_fill_vec_status(vec->status + i, -1, vec->num - i);

	qat_sym_dp_update_tx_queue(qp, tx_queue, tail, i, flags);

	return i;
}

static __rte_always_inline uint32_t
qat_sym_dp_enqueue_cipher(struct rte_cryptodev *dev, uint16_t qp_id,
	union rte_cryptodev_hw_session_ctx session,
	union rte_crypto_sym_ofs ofs, struct rte_crypto_sym_vec *vec,
	void **opaque, uint32_t flags)
{
	struct qat_qp *qp = dev->data->queue_pairs[qp_id];
	struct rte_cryptodev_sym_session *sess;
	struct qat_queue *tx_queue;
	struct qat_sym_session *ctx;
	uint32_t i;
	register uint32_t tail;

	if (unlikely(QAT_SYM_DP_IS_VEC_VALID(qp, flags, vec->num) == 0)) {
		QAT_DP_LOG(ERR, "Operation not supported");
		qat_sym_dp_fill_vec_status(vec->status, -1, vec->num);
		return 0;
	}

	sess = session.crypto_sess;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(sess,
			dev->driver_id);

	tx_queue = &qp->tx_q;
	tail = (tx_queue->tail + qp->cached * tx_queue->msg_size) &
			tx_queue->modulo_mask;

	for (i = 0; i < vec->num; i++) {
		struct icp_qat_fw_la_bulk_req *req;
		struct icp_qat_fw_la_cipher_req_params *cipher_param;
		struct rte_crypto_sgl *sgl = &vec->sgl[i];
		struct rte_crypto_vec *iv_vec = &vec->iv_vec[i];

		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + tail);
		rte_mov128((uint8_t *)req,
			(const uint8_t *)&(ctx->fw_req));

		if (i == 0 || (flags & RTE_CRYPTO_HW_DP_FF_SET_OPAQUE_ARRAY))
			req->comn_mid.opaque_data = (uint64_t)opaque[i];

		cipher_param = (void *)&req->serv_specif_rqpars;

		req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			sgl->vec[0].iova;
		req->comn_mid.src_length = req->comn_mid.dst_length =
			sgl->vec[0].len;

		/* cipher IV */
		set_cipher_iv(cipher_param, iv_vec, ctx->cipher_iv.length, req);
		cipher_param->cipher_offset = ofs.ofs.cipher.head;
		cipher_param->cipher_length = sgl->vec[0].len -
				ofs.ofs.cipher.head - ofs.ofs.cipher.tail;

		/* SGL processing */
		if (unlikely(sgl->num > 1)) {
			int total_len = qat_sym_dp_fill_sgl(qp, req, sgl);

			if (total_len < 0) {
				if (flags & RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
					break;
				/* Give up enqueue if exhaust is not set */
				QAT_DP_LOG(ERR, "Operation not supported");
				qat_sym_dp_fill_vec_status(vec->status, -1,
						vec->num);
				return 0;
			}

			cipher_param->cipher_length = total_len -
				ofs.ofs.cipher.head - ofs.ofs.cipher.tail;
		}

		tail = (tail + tx_queue->msg_size) & tx_queue->modulo_mask;

	}

	qat_sym_dp_update_tx_queue(qp, tx_queue, tail, i, flags);

	return i;
}

static __rte_always_inline uint32_t
qat_sym_dp_enqueue_auth(struct rte_cryptodev *dev, uint16_t qp_id,
	union rte_cryptodev_hw_session_ctx session,
	union rte_crypto_sym_ofs ofs, struct rte_crypto_sym_vec *vec,
	void **opaque, uint32_t flags)
{
	struct qat_qp *qp = dev->data->queue_pairs[qp_id];
	struct rte_cryptodev_sym_session *sess;
	struct qat_queue *tx_queue;
	struct qat_sym_session *ctx;
	uint32_t i;
	register uint32_t tail;

	if (unlikely(QAT_SYM_DP_IS_VEC_VALID(qp, flags, vec->num) == 0)) {
		QAT_DP_LOG(ERR, "Operation not supported");
		qat_sym_dp_fill_vec_status(vec->status, -1, vec->num);
		return 0;
	}

	sess = session.crypto_sess;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(sess,
			dev->driver_id);

	tx_queue = &qp->tx_q;
	tail = (tx_queue->tail + qp->cached * tx_queue->msg_size) &
			tx_queue->modulo_mask;

	for (i = 0; i < vec->num; i++) {
		struct icp_qat_fw_la_bulk_req *req;
		struct icp_qat_fw_la_cipher_req_params *cipher_param;
		struct icp_qat_fw_la_auth_req_params *auth_param;
		struct rte_crypto_sgl *sgl = &vec->sgl[i];
		struct rte_crypto_vec *iv_vec = &vec->iv_vec[i];
		struct rte_crypto_vec *digest_vec = &vec->digest_vec[i];
		int total_len;

		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + tail);
		rte_mov128((uint8_t *)req,
			(const uint8_t *)&(ctx->fw_req));

		if (i == 0 || (flags & RTE_CRYPTO_HW_DP_FF_SET_OPAQUE_ARRAY))
			req->comn_mid.opaque_data = (uint64_t)opaque[i];

		cipher_param = (void *)&req->serv_specif_rqpars;
		auth_param = (void *)((uint8_t *)cipher_param +
				ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
		req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			sgl->vec[0].iova;
		req->comn_mid.src_length = req->comn_mid.dst_length =
			sgl->vec[0].len;

		auth_param->auth_off = ofs.ofs.auth.head;
		auth_param->auth_len = sgl->vec[0].len - ofs.ofs.auth.head -
				ofs.ofs.auth.tail;
		auth_param->auth_res_addr = digest_vec->iova;

		switch (ctx->qat_hash_alg) {
		case ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2:
		case ICP_QAT_HW_AUTH_ALGO_KASUMI_F9:
		case ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3:
			auth_param->u1.aad_adr = iv_vec->iova;
			break;
		case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
		case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
			ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
				req->comn_hdr.serv_specif_flags,
					ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
			rte_memcpy_generic(cipher_param->u.cipher_IV_array,
					iv_vec->base, ctx->cipher_iv.length);
			break;
		default:
			break;
		}

		/* SGL processing */
		if (unlikely(sgl->num > 1)) {
			total_len = qat_sym_dp_fill_sgl(qp, req, sgl);

			if (total_len < 0) {
				if (flags & RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
					break;
				/* Give up enqueue if exhaust is not set */
				QAT_DP_LOG(ERR, "Operation not supported");
				qat_sym_dp_fill_vec_status(vec->status, -1,
						vec->num);
				return 0;
			}

			cipher_param->cipher_length = auth_param->auth_len =
				total_len - ofs.ofs.cipher.head -
				ofs.ofs.cipher.tail;
		}

		tail = (tail + tx_queue->msg_size) & tx_queue->modulo_mask;
	}

	if (unlikely(i < vec->num))
		qat_sym_dp_fill_vec_status(vec->status + i, -1, vec->num - i);

	qat_sym_dp_update_tx_queue(qp, tx_queue, tail, i, flags);

	return i;
}

static __rte_always_inline uint32_t
qat_sym_dp_enqueue_chain(struct rte_cryptodev *dev, uint16_t qp_id,
	union rte_cryptodev_hw_session_ctx session,
	union rte_crypto_sym_ofs ofs, struct rte_crypto_sym_vec *vec,
	void **opaque, uint32_t flags)
{
	struct qat_qp *qp = dev->data->queue_pairs[qp_id];
	struct rte_cryptodev_sym_session *sess;
	struct qat_queue *tx_queue;
	struct qat_sym_session *ctx;
	uint32_t i;
	register uint32_t tail;

	if (unlikely(QAT_SYM_DP_IS_VEC_VALID(qp, flags, vec->num) == 0)) {
		QAT_DP_LOG(ERR, "Operation not supported");
		qat_sym_dp_fill_vec_status(vec->status, -1, vec->num);
		return 0;
	}

	sess = session.crypto_sess;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(sess,
			dev->driver_id);

	tx_queue = &qp->tx_q;
	tail = (tx_queue->tail + qp->cached * tx_queue->msg_size) &
			tx_queue->modulo_mask;

	for (i = 0; i < vec->num; i++) {
		struct icp_qat_fw_la_bulk_req *req;
		struct icp_qat_fw_la_cipher_req_params *cipher_param;
		struct icp_qat_fw_la_auth_req_params *auth_param;
		struct rte_crypto_sgl *sgl = &vec->sgl[i];
		struct rte_crypto_vec *iv_vec = &vec->iv_vec[i];
		struct rte_crypto_vec *digest_vec = &vec->digest_vec[i];
		rte_iova_t auth_iova_end;
		int total_len;

		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + tail);
		rte_mov128((uint8_t *)req,
			(const uint8_t *)&(ctx->fw_req));

		if (i == 0 || (flags & RTE_CRYPTO_HW_DP_FF_SET_OPAQUE_ARRAY))
			req->comn_mid.opaque_data = (uint64_t)opaque[i];

		cipher_param = (void *)&req->serv_specif_rqpars;
		auth_param = (void *)((uint8_t *)cipher_param +
				ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
		req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			sgl->vec[0].iova;
		req->comn_mid.src_length = req->comn_mid.dst_length =
			sgl->vec[0].len;

		cipher_param->cipher_offset = ofs.ofs.cipher.head;
		cipher_param->cipher_length = sgl->vec[0].len -
				ofs.ofs.cipher.head - ofs.ofs.cipher.tail;
		set_cipher_iv(cipher_param, iv_vec, ctx->cipher_iv.length, req);

		auth_param->auth_off = ofs.ofs.cipher.head;
		auth_param->auth_len = sgl->vec[0].len -
				ofs.ofs.auth.head - ofs.ofs.auth.tail;
		auth_param->auth_res_addr = digest_vec->iova;

		/* SGL processing */
		if (unlikely(sgl->num > 1)) {
			total_len = qat_sym_dp_fill_sgl(qp, req, sgl);

			if (total_len < 0) {
				if (flags & RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
					break;
				/* Give up enqueue if exhaust is not set */
				QAT_DP_LOG(ERR, "Operation not supported");
				qat_sym_dp_fill_vec_status(vec->status, -1,
						vec->num);
				return 0;
			}

			cipher_param->cipher_length = auth_param->auth_len =
				total_len - ofs.ofs.cipher.head -
				ofs.ofs.cipher.tail;
		}

		switch (ctx->qat_hash_alg) {
		case ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2:
		case ICP_QAT_HW_AUTH_ALGO_KASUMI_F9:
		case ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3:
			auth_param->u1.aad_adr = iv_vec->iova;

			if (unlikely(sgl->num > 1)) {
				int auth_end_get = 0, i = sgl->num - 1;
				struct rte_crypto_vec *cvec = &sgl->vec[i];
				uint32_t len;

				if (total_len - ofs.ofs.auth.tail < 0) {
					if (flags &
					RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
						break;
					/* Give up enqueue if exhaust not set */
					QAT_DP_LOG(ERR, "Incorrect length");
					qat_sym_dp_fill_vec_status(vec->status,
						-1, vec->num);
					return 0;
				}

				len = total_len - ofs.ofs.auth.tail;

				while (i >= 0 && len > 0) {
					if (cvec->len >= len) {
						auth_iova_end = cvec->iova +
							(cvec->len - len);
						len = 0;
						auth_end_get = 1;
						break;
					}
					len -= cvec->len;
					i--;
					vec--;
				}

				if (!auth_end_get) {
					QAT_DP_LOG(ERR, "Failed to get end");
					if (flags &
					RTE_CRYPTO_HW_DP_FF_ENQUEUE_EXHAUST)
						break;
					/* Give up enqueue if exhaust not set */
					QAT_DP_LOG(ERR, "Incorrect length");
					qat_sym_dp_fill_vec_status(vec->status,
						-1, vec->num);
					return 0;
				}
			} else
				auth_iova_end = digest_vec->iova +
					digest_vec->len;

			/* Then check if digest-encrypted conditions are met */
			if ((auth_param->auth_off + auth_param->auth_len <
					cipher_param->cipher_offset +
					cipher_param->cipher_length) &&
					(digest_vec->iova == auth_iova_end)) {
				/* Handle partial digest encryption */
				if (cipher_param->cipher_offset +
						cipher_param->cipher_length <
						auth_param->auth_off +
						auth_param->auth_len +
						ctx->digest_length)
					req->comn_mid.dst_length =
						req->comn_mid.src_length =
						auth_param->auth_off +
						auth_param->auth_len +
						ctx->digest_length;
				struct icp_qat_fw_comn_req_hdr *header =
					&req->comn_hdr;
				ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(
					header->serv_specif_flags,
					ICP_QAT_FW_LA_DIGEST_IN_BUFFER);
			}
			break;
		case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
		case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
			QAT_DP_LOG(ERR, "GMAC as auth algo not supported");
			return -1;
		default:
			break;
		}

		tail = (tail + tx_queue->msg_size) & tx_queue->modulo_mask;
	}

	if (unlikely(i < vec->num))
		qat_sym_dp_fill_vec_status(vec->status + i, -1, vec->num - i);

	qat_sym_dp_update_tx_queue(qp, tx_queue, tail, i, flags);

	return i;
}

static __rte_always_inline uint32_t
qat_sym_dp_dequeue(struct rte_cryptodev *dev, uint16_t qp_id,
	rte_cryptodev_get_dequeue_count_t get_dequeue_count,
	rte_cryptodev_post_dequeue_t post_dequeue,
	void **out_opaque,
	uint32_t *n_success_jobs, uint32_t flags)
{
	struct qat_qp *qp = dev->data->queue_pairs[qp_id];
	register struct qat_queue *rx_queue;
	struct icp_qat_fw_comn_resp *resp, *last_resp = 0;
	void *resp_opaque;
	uint32_t i, n;
	uint32_t head;
	uint8_t status;

	*n_success_jobs = 0;
	rx_queue = &qp->rx_q;
	head = rx_queue->head;

	resp = (struct icp_qat_fw_comn_resp *)((uint8_t *)rx_queue->base_addr +
			head);
	/* no operation ready */
	if (unlikely(*(uint32_t *)resp == ADF_RING_EMPTY_SIG))
		return 0;

	resp_opaque = (void *)(uintptr_t)resp->opaque_data;
	/* get the dequeue count */
	n = get_dequeue_count(resp_opaque);
	assert(n > 0);

	out_opaque[0] = resp_opaque;
	head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;
	status = QAT_SYM_DP_IS_RESP_SUCCESS(resp);
	post_dequeue(resp_opaque, 0, status);
	*n_success_jobs += status;

	/* we already finished dequeue when n == 1 */
	if (unlikely(n == 1)) {
		i = 1;
		goto update_rx_queue;
	}

	last_resp = (struct icp_qat_fw_comn_resp *)(
		(uint8_t *)rx_queue->base_addr + ((head + rx_queue->msg_size *
			(n - 2)) & rx_queue->modulo_mask));

	/* if EXAUST is not set, check if we can dequeue that many jobs */
	if (flags & RTE_CRYPTO_HW_DP_FF_DEQUEUE_EXHAUST) {
		if (flags & RTE_CRYPTO_HW_DP_FF_GET_OPAQUE_ARRAY) {
			for (i = 1; i < n - 1; i++) {
				resp = (struct icp_qat_fw_comn_resp *)(
					(uint8_t *)rx_queue->base_addr + head);
				if (unlikely(*(uint32_t *)resp ==
						ADF_RING_EMPTY_SIG))
					goto update_rx_queue;
				out_opaque[i] = (void *)(uintptr_t)
						resp->opaque_data;
				status = QAT_SYM_DP_IS_RESP_SUCCESS(resp);
				*n_success_jobs += status;
				post_dequeue(out_opaque[i], i, status);
				head = (head + rx_queue->msg_size) &
						rx_queue->modulo_mask;
			}

			status = QAT_SYM_DP_IS_RESP_SUCCESS(last_resp);
			out_opaque[i] = (void *)(uintptr_t)
					last_resp->opaque_data;
			post_dequeue(out_opaque[i], i, status);
			*n_success_jobs += status;
			i++;
			head = (head + rx_queue->msg_size) &
					rx_queue->modulo_mask;
			goto update_rx_queue;
		}

		/* (flags & RTE_CRYPTO_HW_DP_FF_GET_OPAQUE_ARRAY) == 0 */
		for (i = 1; i < n - 1; i++) {
			resp = (struct icp_qat_fw_comn_resp *)(
				(uint8_t *)rx_queue->base_addr + head);
			status = QAT_SYM_DP_IS_RESP_SUCCESS(resp);
			if (unlikely(*(uint32_t *)resp == ADF_RING_EMPTY_SIG))
				goto update_rx_queue;
			head = (head + rx_queue->msg_size) &
					rx_queue->modulo_mask;
			post_dequeue(resp_opaque, i, status);
			*n_success_jobs += status;
		}
		status = QAT_SYM_DP_IS_RESP_SUCCESS(last_resp);
		post_dequeue(resp_opaque, i, status);
		*n_success_jobs += status;
		i++;
		head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;
		goto update_rx_queue;
	}

	/* not all operation ready */
	if (unlikely(*(uint32_t *)last_resp == ADF_RING_EMPTY_SIG))
		return 0;

	if (flags & RTE_CRYPTO_HW_DP_FF_GET_OPAQUE_ARRAY) {
		for (i = 1; i < n - 1; i++) {
			uint8_t status;

			resp = (struct icp_qat_fw_comn_resp *)(
				(uint8_t *)rx_queue->base_addr + head);
			out_opaque[i] = (void *)(uintptr_t)resp->opaque_data;
			status = QAT_SYM_DP_IS_RESP_SUCCESS(resp);
			*n_success_jobs += status;
			post_dequeue(out_opaque[i], i, status);
			head = (head + rx_queue->msg_size) &
					rx_queue->modulo_mask;
		}
		out_opaque[i] = (void *)(uintptr_t)last_resp->opaque_data;
		post_dequeue(out_opaque[i], i,
				QAT_SYM_DP_IS_RESP_SUCCESS(last_resp));
		i++;
		head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;
		goto update_rx_queue;
	}

	/* (flags & RTE_CRYPTO_HW_DP_FF_GET_OPAQUE_ARRAY) == 0 */
	for (i = 1; i < n - 1; i++) {
		resp = (struct icp_qat_fw_comn_resp *)(
			(uint8_t *)rx_queue->base_addr + head);
		status = QAT_SYM_DP_IS_RESP_SUCCESS(resp);
		*n_success_jobs += status;
		post_dequeue(resp_opaque, i, status);
		head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;
	}

	status = QAT_SYM_DP_IS_RESP_SUCCESS(resp);
	head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;
	i++;
	*n_success_jobs += status;
	post_dequeue(resp_opaque, i, status);

update_rx_queue:
	rx_queue->head = head;
	rx_queue->nb_processed_responses += i;
	qp->dequeued += i;
	qp->stats.dequeued_count += i;
	if (rx_queue->nb_processed_responses > QAT_CSR_HEAD_WRITE_THRESH) {
		uint32_t old_head, new_head;
		uint32_t max_head;

		old_head = rx_queue->csr_head;
		new_head = rx_queue->head;
		max_head = qp->nb_descriptors * rx_queue->msg_size;

		/* write out free descriptors */
		void *cur_desc = (uint8_t *)rx_queue->base_addr + old_head;

		if (new_head < old_head) {
			memset(cur_desc, ADF_RING_EMPTY_SIG_BYTE,
					max_head - old_head);
			memset(rx_queue->base_addr, ADF_RING_EMPTY_SIG_BYTE,
					new_head);
		} else {
			memset(cur_desc, ADF_RING_EMPTY_SIG_BYTE, new_head -
					old_head);
		}
		rx_queue->nb_processed_responses = 0;
		rx_queue->csr_head = new_head;

		/* write current head to CSR */
		WRITE_CSR_RING_HEAD(qp->mmap_bar_addr,
			rx_queue->hw_bundle_number, rx_queue->hw_queue_number,
			new_head);
	}

	return i;
}

struct rte_crytodev_sym_hw_dp_ops qat_hw_dp_ops = {
	.enqueue_aead = qat_sym_dp_enqueue_aead,
	.enqueue_cipher = qat_sym_dp_enqueue_cipher,
	.enqueue_auth = qat_sym_dp_enqueue_auth,
	.enqueue_chain = qat_sym_dp_enqueue_chain,
	.dequeue = qat_sym_dp_dequeue
};

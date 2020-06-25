/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2019 Intel Corporation
 */

#include <rte_cryptodev_pmd.h>

#include "adf_transport_access_macros.h"
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"

#include "qat_sym.h"
#include "qat_sym_pmd.h"
#include "qat_sym_session.h"
#include "qat_sym_frame.h"
#include "qat_qp.h"

void *
qat_sym_get_qp(uint8_t dev_id, uint16_t qp_id)
{
	struct rte_cryptodev *dev;
	struct qat_qp *qp;
	const char *drv_name;

	/* make sure it is a QAT device */
	if (!rte_cryptodev_get_qp_status(dev_id, qp_id))
		return NULL;

	dev = rte_cryptodev_pmd_get_dev(dev_id);
	drv_name = rte_cryptodev_driver_name_get(dev->driver_id);
	if ((strncmp(drv_name, RTE_STR(CRYPTODEV_NAME_QAT_SYM_PMD),
			sizeof(RTE_STR(CRYPTODEV_NAME_QAT_SYM_PMD))) != 0) ||
			(qp_id > dev->data->nb_queue_pairs))
		return NULL;

	qp = dev->data->queue_pairs[qp_id];
	if (qp->service_type != QAT_SERVICE_SYMMETRIC)
		return NULL;

	return (void *)qp;
}

static __rte_always_inline int
qat_sym_frame_fill_sgl(struct qat_qp *qp, struct icp_qat_fw_la_bulk_req *req,
		struct rte_crypto_sgl *sgl, uint32_t max_len)
{
	struct qat_queue *tx_queue = &qp->tx_q;
	struct qat_sym_op_cookie *cookie;
	struct qat_sgl *list;
	int64_t len = max_len;
	uint32_t i;

	if (!sgl)
		return -EINVAL;
	if (sgl->num < 2 || sgl->num > QAT_SYM_SGL_MAX_NUMBER || !sgl->vec)
		return -EINVAL;

	ICP_QAT_FW_COMN_PTR_TYPE_SET(req->comn_hdr.comn_req_flags,
			QAT_COMN_PTR_TYPE_SGL);
	cookie = qp->op_cookies[tx_queue->tail >> tx_queue->trailz];
	list = (struct qat_sgl *)&cookie->qat_sgl_src;

	for (i = 0; i < sgl->num && len > 0; i++) {
		list->buffers[i].len = RTE_MIN(sgl->vec[i].len, len);
		list->buffers[i].resrvd = 0;
		list->buffers[i].addr = sgl->vec[i].iova;
		len -= list->buffers[i].len;
	}

	if (unlikely(len > 0))
		return -1;

	list->num_bufs = i;
	req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			cookie->qat_sgl_src_phys_addr;
	req->comn_mid.src_length = req->comn_mid.dst_length = 0;
	return 0;
}

static __rte_always_inline void
qat_sym_set_cipher_param(struct icp_qat_fw_la_cipher_req_params *cipher_param,
		uint32_t cipher_ofs, uint32_t cipher_len)
{
	cipher_param->cipher_offset = cipher_ofs;
	cipher_param->cipher_length = cipher_len;
}

static __rte_always_inline void
qat_sym_set_auth_param(struct icp_qat_fw_la_auth_req_params *auth_param,
		uint32_t auth_ofs, uint32_t auth_len,
		rte_iova_t digest_iova, rte_iova_t aad_iova)
{
	auth_param->auth_off = auth_ofs;
	auth_param->auth_len = auth_len;
	auth_param->auth_res_addr = digest_iova;
	auth_param->u1.aad_adr = aad_iova;
}

int
qat_sym_enqueue_frame_aead(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		struct qat_sym_job *job, uint32_t *tail,
		uint8_t is_first, uint8_t is_last, void *frame)
{
	struct qat_qp *qp = qat_sym_qp;
	struct qat_queue *tx_queue = &qp->tx_q;
	struct qat_sym_session *ctx;
	register struct icp_qat_fw_la_bulk_req *req;
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	uint32_t t;
	/* In case of AES-CCM this may point to user selected
	 * memory or iv offset in cypto_op
	 */
	uint8_t *aad_data;
	/* This is true AAD length, it not includes 18 bytes of
	 * preceding data
	 */
	uint8_t aad_ccm_real_len;
	uint8_t aad_len_field_sz;
	uint32_t msg_len_be;
	rte_iova_t aad_iova;
	uint8_t q;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(
		session, cryptodev_qat_driver_id);

	if (unlikely(is_first != 0)) {
		t = tx_queue->tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + t);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
		req->comn_mid.opaque_data = (uintptr_t)frame;
	} else {
		t = *tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + t);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
	}

	cipher_param = (void *)&req->serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param +
			ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);

	req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			job->data_iova;
	req->comn_mid.src_length = req->comn_mid.dst_length =
			job->aead.aead_ofs + job->aead.aead_len;

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
		ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
			req->comn_hdr.serv_specif_flags,
				ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
		rte_memcpy_generic(cipher_param->u.cipher_IV_array,
				job->iv, ctx->cipher_iv.length);
		aad_iova = job->aead.aad_iova;
		break;
	case ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC:
		aad_data = job->aead.aad;
		aad_iova = job->aead.aad_iova;
		aad_ccm_real_len = 0;
		aad_len_field_sz = 0;
		msg_len_be = rte_bswap32(job->aead.aead_len);

		if (ctx->aad_len > ICP_QAT_HW_CCM_AAD_DATA_OFFSET) {
			aad_len_field_sz = ICP_QAT_HW_CCM_AAD_LEN_INFO;
			aad_ccm_real_len = ctx->aad_len -
					ICP_QAT_HW_CCM_AAD_B0_LEN -
					ICP_QAT_HW_CCM_AAD_LEN_INFO;
		} else {
			aad_data = job->iv;
			aad_iova = job->iv_iova;
		}

		q = ICP_QAT_HW_CCM_NQ_CONST - ctx->cipher_iv.length;
		aad_data[0] = ICP_QAT_HW_CCM_BUILD_B0_FLAGS(aad_len_field_sz,
				ctx->digest_length, q);
		if (q > ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE) {
			memcpy(aad_data	+ ctx->cipher_iv.length +
			    ICP_QAT_HW_CCM_NONCE_OFFSET +
			    (q - ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE),
			    (uint8_t *)&msg_len_be,
			    ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE);
		} else {
			memcpy(aad_data	+ ctx->cipher_iv.length +
			    ICP_QAT_HW_CCM_NONCE_OFFSET,
			    (uint8_t *)&msg_len_be
			    + (ICP_QAT_HW_CCM_MSG_LEN_MAX_FIELD_SIZE
			    - q), q);
		}

		if (aad_len_field_sz > 0) {
			*(uint16_t *)&aad_data[ICP_QAT_HW_CCM_AAD_B0_LEN] =
					rte_bswap16(aad_ccm_real_len);

			if ((aad_ccm_real_len + aad_len_field_sz)
					% ICP_QAT_HW_CCM_AAD_B0_LEN) {
				uint8_t pad_len = 0;
				uint8_t pad_idx = 0;

				pad_len = ICP_QAT_HW_CCM_AAD_B0_LEN -
				((aad_ccm_real_len + aad_len_field_sz) %
					ICP_QAT_HW_CCM_AAD_B0_LEN);
				pad_idx = ICP_QAT_HW_CCM_AAD_B0_LEN +
				    aad_ccm_real_len + aad_len_field_sz;
				memset(&aad_data[pad_idx], 0, pad_len);
			}

			rte_memcpy(((uint8_t *)cipher_param->u.cipher_IV_array)
					+ ICP_QAT_HW_CCM_NONCE_OFFSET,
					job->iv + ICP_QAT_HW_CCM_NONCE_OFFSET,
					ctx->cipher_iv.length);
			*(uint8_t *)&cipher_param->u.cipher_IV_array[0] =
				q - ICP_QAT_HW_CCM_NONCE_OFFSET;

			if (aad_len_field_sz)
				rte_memcpy(job->aead.aad +
					ICP_QAT_HW_CCM_NONCE_OFFSET,
					job->iv + ICP_QAT_HW_CCM_NONCE_OFFSET,
					ctx->cipher_iv.length);

		}
		break;
	default:
		return -1;
	}

	qat_sym_set_cipher_param(cipher_param, job->aead.aead_ofs,
			job->aead.aead_len);
	qat_sym_set_auth_param(auth_param, job->aead.aead_ofs,
			job->aead.aead_len, job->aead.tag_iova, aad_iova);

	if (unlikely(job->flags & QAT_SYM_DESC_FLAG_IS_SGL) != 0) {
		int ret = qat_sym_frame_fill_sgl(qp, req, job->sgl,
				job->aead.aead_ofs + job->aead.aead_len);
		if (unlikely(ret < 0))
			return -1;
	}

	if (ctx->is_single_pass) {
		cipher_param->spc_aad_addr = aad_iova;
		cipher_param->spc_auth_res_addr = job->aead.tag_iova;
	}

	qp->enqueued++;
	qp->stats.enqueued_count++;

	if (unlikely(is_last != 0)) {
		tx_queue->tail = (t + tx_queue->msg_size) &
				tx_queue->modulo_mask;
		WRITE_CSR_RING_TAIL(qp->mmap_bar_addr,
			tx_queue->hw_bundle_number,
			tx_queue->hw_queue_number,
			tx_queue->tail);
		tx_queue->csr_tail = tx_queue->tail;
	} else
		*tail = (t + tx_queue->msg_size) & tx_queue->modulo_mask;

	return 0;
}


int
qat_sym_enqueue_frame_cipher(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		struct qat_sym_job *job, uint32_t *tail,
		uint8_t is_first, uint8_t is_last, void *frame)
{
	struct qat_qp *qp = qat_sym_qp;
	struct qat_queue *tx_queue = &qp->tx_q;
	struct qat_sym_session *ctx;
	struct icp_qat_fw_la_bulk_req *req;
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	uint32_t t;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(
			session, cryptodev_qat_driver_id);
	if (unlikely(ctx->bpi_ctx)) {
		QAT_DP_LOG(ERR, "DOCSIS is not supported");
		return -1;
	}

	if (unlikely(is_first != 0)) {
		t = tx_queue->tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + t);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
		req->comn_mid.opaque_data = (uintptr_t)frame;
	} else {
		t = *tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + t);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
	}

	cipher_param = (void *)&req->serv_specif_rqpars;

	req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			job->data_iova;
	req->comn_mid.src_length = req->comn_mid.dst_length =
			job->cipher_only.cipher_ofs +
			job->cipher_only.cipher_len;

	/* cipher IV */
	rte_memcpy_generic(cipher_param->u.cipher_IV_array,
			job->iv, ctx->cipher_iv.length);
	qat_sym_set_cipher_param(cipher_param, job->cipher_only.cipher_ofs,
			job->cipher_only.cipher_len);

	if (unlikely((job->flags & QAT_SYM_DESC_FLAG_IS_SGL) != 0)) {
		int ret = qat_sym_frame_fill_sgl(qp, req, job->sgl,
				job->cipher_only.cipher_ofs +
				job->cipher_only.cipher_len);
		if (unlikely(ret < 0))
			return -1;
	}

	qp->enqueued++;
	qp->stats.enqueued_count++;

	if (unlikely(is_last != 0)) {
		tx_queue->tail = (t + tx_queue->msg_size) &
			tx_queue->modulo_mask;
		WRITE_CSR_RING_TAIL(qp->mmap_bar_addr,
			tx_queue->hw_bundle_number,
			tx_queue->hw_queue_number,
			tx_queue->tail);
		tx_queue->csr_tail = tx_queue->tail;
	} else
		*tail = (t + tx_queue->msg_size) & tx_queue->modulo_mask;

	return 0;
}

int
qat_sym_enqueue_frame_auth(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		struct qat_sym_job *job, uint32_t *tail,
		uint8_t is_first, uint8_t is_last, void *frame)
{
	struct qat_qp *qp = qat_sym_qp;
	struct qat_queue *tx_queue = &qp->tx_q;
	struct qat_sym_session *ctx;
	struct icp_qat_fw_la_bulk_req *req;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	uint32_t t;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(
			session, cryptodev_qat_driver_id);

	if (unlikely(is_first != 0)) {
		t = tx_queue->tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + tx_queue->tail);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
		req->comn_mid.opaque_data = (uintptr_t)frame;
	} else {
		t = *tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + *tail);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
	}

	auth_param = (void *)((uint8_t *)&req->serv_specif_rqpars +
			ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
	if (unlikely(is_first != 0))
		req->comn_mid.opaque_data = (uintptr_t)frame;

	req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr =
			job->data_iova;
	req->comn_mid.src_length = req->comn_mid.dst_length =
			job->auth_only.auth_ofs + job->auth_only.auth_len;

	/* auth */
	qat_sym_set_auth_param(auth_param, job->auth_only.auth_ofs,
		job->auth_only.auth_len, job->auth_only.digest_iova, 0);

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2:
	case ICP_QAT_HW_AUTH_ALGO_KASUMI_F9:
	case ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3:
		auth_param->u1.aad_adr = job->iv_iova;
		break;
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_128:
	case ICP_QAT_HW_AUTH_ALGO_GALOIS_64:
		QAT_DP_LOG(ERR, "GMAC as chained auth algo is not supported");
		return -1;
	default:
		break;
	}

	if (unlikely((job->flags & QAT_SYM_DESC_FLAG_IS_SGL) != 0)) {
		int ret = qat_sym_frame_fill_sgl(qp, req, job->sgl,
				job->auth_only.auth_ofs +
				job->auth_only.auth_len);
		if (unlikely(ret < 0))
			return -1;
	}

	qp->enqueued++;
	qp->stats.enqueued_count++;

	if (unlikely(is_last != 0)) {
		tx_queue->tail = (t + tx_queue->msg_size) &
			tx_queue->modulo_mask;
		WRITE_CSR_RING_TAIL(qp->mmap_bar_addr,
			tx_queue->hw_bundle_number,
			tx_queue->hw_queue_number,
			tx_queue->tail);
		tx_queue->csr_tail = tx_queue->tail;
	} else
		*tail = (t + tx_queue->msg_size) & tx_queue->modulo_mask;

	return 0;
}

int
qat_sym_enqueue_frame_chain(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		struct qat_sym_job *job, uint32_t *tail,
		uint8_t is_first, uint8_t is_last, void *frame)
{
	struct qat_qp *qp = qat_sym_qp;
	struct qat_queue *tx_queue = &qp->tx_q;
	struct qat_sym_session *ctx;
	struct icp_qat_fw_la_bulk_req *req;
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	uint32_t min_ofs = RTE_MIN(job->chain.cipher_ofs, job->chain.auth_ofs);
	uint32_t max_len = RTE_MAX(job->chain.cipher_len, job->chain.auth_len);
	rte_iova_t auth_iova_end;
	uint32_t t;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(
			session, cryptodev_qat_driver_id);
	if (unlikely(ctx->bpi_ctx)) {
		QAT_DP_LOG(ERR, "DOCSIS is not supported");
		return -1;
	}

	if (unlikely(is_first != 0)) {
		t = tx_queue->tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + t);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
		req->comn_mid.opaque_data = (uintptr_t)frame;
	} else {
		t = *tail;
		req  = (struct icp_qat_fw_la_bulk_req *)(
			(uint8_t *)tx_queue->base_addr + t);
		rte_mov128((uint8_t *)req, (const uint8_t *)&(ctx->fw_req));
	}

	cipher_param = (void *)&req->serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param +
			ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
	if (unlikely(is_first != 0))
		req->comn_mid.opaque_data = (uintptr_t)frame;

	req->comn_mid.src_data_addr =
		req->comn_mid.dest_data_addr = job->data_iova;
	req->comn_mid.src_length = req->comn_mid.dst_length = min_ofs + max_len;

	/* cipher IV */
	rte_memcpy_generic(cipher_param->u.cipher_IV_array,
			job->iv, ctx->cipher_iv.length);
	qat_sym_set_cipher_param(cipher_param, job->chain.cipher_ofs,
			job->chain.cipher_len);

	/* auth */
	qat_sym_set_auth_param(auth_param, job->chain.auth_ofs,
			job->chain.auth_len, job->chain.digest_iova, 0);

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2:
	case ICP_QAT_HW_AUTH_ALGO_KASUMI_F9:
	case ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3:
		auth_param->u1.aad_adr = job->iv_iova;

		if (unlikely(job->flags & QAT_SYM_DESC_FLAG_IS_SGL)) {
			uint32_t len = job->chain.auth_ofs +
					job->chain.auth_len;
			struct rte_crypto_vec *vec = job->sgl->vec;
			int auth_end_get = 0;
			while (len) {
				if (len <= vec->len) {
					auth_iova_end = vec->iova + len;
					auth_end_get = 1;
					break;
				}
				len -= vec->len;
				vec++;
			}
			if (!auth_end_get) {
				QAT_DP_LOG(ERR, "Failed to get auth end");
				return -1;
			}
		} else
			auth_iova_end = job->data_iova + job->chain.auth_ofs +
				job->chain.auth_len;

		/* Then check if digest-encrypted conditions are met */
		if ((auth_param->auth_off + auth_param->auth_len <
				cipher_param->cipher_offset +
				cipher_param->cipher_length) &&
				(job->chain.digest_iova == auth_iova_end)) {
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
		QAT_DP_LOG(ERR, "GMAC as chained auth algo is not supported");
		return -1;
	default:
		break;
	}

	if (unlikely((job->flags & QAT_SYM_DESC_FLAG_IS_SGL) != 0)) {
		int ret = qat_sym_frame_fill_sgl(qp, req, job->sgl,
				min_ofs + max_len);
		if (unlikely(ret < 0))
			return -1;
	}

	qp->enqueued++;
	qp->stats.enqueued_count++;

	if (unlikely(is_last != 0)) {
		tx_queue->tail = (t + tx_queue->msg_size) &
			tx_queue->modulo_mask;
		WRITE_CSR_RING_TAIL(qp->mmap_bar_addr,
			tx_queue->hw_bundle_number,
			tx_queue->hw_queue_number,
			tx_queue->tail);
		tx_queue->csr_tail = tx_queue->tail;
	} else
		*tail = (t + tx_queue->msg_size) & tx_queue->modulo_mask;

	return 0;
}

#define get_rx_queue_message_at_index(q, h, i) \
	(void *)((uint8_t *)q->base_addr + ((h + q->msg_size * (i)) & \
	q->modulo_mask))

static __rte_always_inline int
qat_is_rx_msg_ok(struct icp_qat_fw_comn_resp *resp_msg)
{
	return ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
			ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(
					resp_msg->comn_hdr.comn_status);
}

int
qat_sym_dequeue_frame(void *qat_sym_qp, void **frame,
		qat_qp_get_frame_n_element_t get_frame_n_elt,
		uint32_t first_status_offset, uint32_t element_interval,
		uint8_t element_status_success, uint8_t element_status_error)
{
	struct qat_qp *qp = qat_sym_qp;
	struct qat_queue *rx_queue = &qp->rx_q;
	struct icp_qat_fw_comn_resp *resp, *resp1, *resp2, *resp3, *respl;
	void *f = NULL;
	uint32_t n_elts, i;
	uint8_t *status, *status1, *status2, *status3;
	int n_fail = 0, n_fail1 = 0, n_fail2 = 0, n_fail3 = 0;
	uint32_t head = rx_queue->head;

	resp = (struct icp_qat_fw_comn_resp *)(
			(uint8_t *)rx_queue->base_addr + head);

	/* if message is not processed, return 0 */
	if (*(uint32_t *)resp == ADF_RING_EMPTY_SIG) {
		*frame = NULL;
		return -1;
	}

	f = (void *)(uintptr_t)resp->opaque_data;
	if (unlikely(f == NULL)) {
		*frame = NULL;
		return -1;
	}

	*frame = f;
	status = (uint8_t *)f + first_status_offset;

	n_elts = (*get_frame_n_elt)(f);
	if (unlikely(n_elts == 0))
		return -1;

	/* process the first message */
	if (qat_is_rx_msg_ok(resp))
		*status = element_status_success;
	else {
		*status = element_status_error;
		n_fail--;
	}

	/* get the last message */
	respl = (struct icp_qat_fw_comn_resp *)(
		(uint8_t *)rx_queue->base_addr + ((head +
			rx_queue->msg_size * (n_elts - 1)) &
				rx_queue->modulo_mask));
	if (*(uint32_t *)respl == ADF_RING_EMPTY_SIG) {
		*frame = NULL;
		return -1;
	}

	status += element_interval;
	head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;

	/* fetch 4 messages in a loop */
	for (i = 1; i > 4 && i < n_elts - 4; i += 4) {
		resp = get_rx_queue_message_at_index(rx_queue, head, 0);
		resp1 = get_rx_queue_message_at_index(rx_queue, head, 1);
		resp2 = get_rx_queue_message_at_index(rx_queue, head, 2);
		resp3 = get_rx_queue_message_at_index(rx_queue, head, 3);

		status1 = status + element_interval;
		status2 = status + element_interval * 2;
		status3 = status + element_interval * 3;

		if (qat_is_rx_msg_ok(resp))
			*status = element_status_success;
		else {
			*status = element_status_error;
			n_fail--;
		}

		if (qat_is_rx_msg_ok(resp1))
			*status1 = element_status_success;
		else {
			*status1 = element_status_error;
			n_fail1--;
		}

		if (qat_is_rx_msg_ok(resp2))
			*status2 = element_status_success;
		else {
			*status2 = element_status_error;
			n_fail2--;
		}

		if (qat_is_rx_msg_ok(resp3))
			*status3 = element_status_success;
		else {
			*status3 = element_status_error;
			n_fail3--;
		}

		i += 4;
		status = status3 + element_interval;
		head = (head + rx_queue->msg_size * 4) & rx_queue->modulo_mask;
	}

	for (; i < n_elts - 1; i++) {
		resp = get_rx_queue_message_at_index(rx_queue, head, 0);
		if (qat_is_rx_msg_ok(resp))
			*status = element_status_success;
		else {
			*status = element_status_error;
			n_fail--;
		}
		status += element_interval;
		head = (head + rx_queue->msg_size) & rx_queue->modulo_mask;
	}

	/* fill the last status field */
	if (qat_is_rx_msg_ok(respl))
		*status = element_status_success;
	else {
		*status = element_status_error;
		n_fail--;
	}

	/* update queue pair head */
	rx_queue->head = head;
	rx_queue->nb_processed_responses += i;
	qp->dequeued += i;
	qp->stats.dequeued_count += i;
	if (rx_queue->nb_processed_responses > QAT_CSR_HEAD_WRITE_THRESH)
		rxq_free_desc(qp, rx_queue);

	return n_fail + n_fail1 + n_fail2 + n_fail3;
}

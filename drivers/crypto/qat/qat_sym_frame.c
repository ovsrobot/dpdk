/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2019 Intel Corporation
 */

#include <rte_cryptodev_pmd.h>

#include "adf_transport_access_macros.h"
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"

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
	if (!rte_cryptodev_pmd_is_valid_dev(dev_id))
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

int
qat_sym_enqueue_frame_aead(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		rte_iova_t data_iova, uint32_t cipher_ofs, uint32_t cipher_len,
		struct rte_crypto_vec *sgl, uint32_t n_sgl_vecs,
		uint8_t *iv, rte_iova_t tag_iova, rte_iova_t aad_iova,
		uint8_t is_first, uint8_t is_last, void *frame)
{
	struct qat_qp *qp = qat_sym_qp;
	struct qat_queue *tx_queue = &qp->tx_q;
	register uint8_t *msg = (uint8_t *)tx_queue->base_addr +
			tx_queue->tail;
	struct qat_sym_session *ctx;
	struct icp_qat_fw_la_bulk_req *req =
			(struct icp_qat_fw_la_bulk_req *)msg;
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;

	ctx = (struct qat_sym_session *)get_sym_session_private_data(
			session, cryptodev_qat_driver_id);
	rte_mov128(msg, (const uint8_t *)&(ctx->fw_req));

	cipher_param = (void *)&req->serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param +
			ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
	req->comn_mid.src_data_addr = req->comn_mid.dest_data_addr = data_iova;
	req->comn_mid.src_length = req->comn_mid.dst_length = cipher_ofs +
			cipher_len;

	/* TODO: add support to non-gcm algorithms */
	if (ctx->qat_hash_alg != ICP_QAT_HW_AUTH_ALGO_GALOIS_128 &&
		ctx->qat_hash_alg != ICP_QAT_HW_AUTH_ALGO_GALOIS_64)
		return -1;

	/* since we know it is GCM, iv has to be 12 bytes */
	ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
			req->comn_hdr.serv_specif_flags,
			ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);

	if (unlikely(is_first != 0))
		req->comn_mid.opaque_data = (uintptr_t)frame;

	rte_memcpy_generic(cipher_param->u.cipher_IV_array, iv,
			ctx->auth_iv.length);

	if (ctx->is_single_pass) {
		cipher_param->spc_aad_addr = aad_iova;
		cipher_param->spc_auth_res_addr = tag_iova;
	}

	if (sgl) {
		if (!n_sgl_vecs)
			return -1;
		/* TODO: sgl process */
	} else {
		cipher_param->cipher_offset = cipher_ofs;
		cipher_param->cipher_length = cipher_len;
		auth_param->auth_off = cipher_ofs;
		auth_param->auth_len = cipher_len;
		auth_param->u1.aad_adr = aad_iova;
		auth_param->auth_res_addr = tag_iova;
	}

	tx_queue->tail = (tx_queue->tail + tx_queue->msg_size) &
			tx_queue->modulo_mask;

	if (unlikely(is_last != 0)) {
		qp->enqueued++;
		qp->stats.enqueued_count++;
		WRITE_CSR_RING_TAIL(qp->mmap_bar_addr,
				tx_queue->hw_bundle_number,
				tx_queue->hw_queue_number,
				tx_queue->tail);
		tx_queue->csr_tail = tx_queue->tail;
	}

	return 0;
}

int
qat_sym_enqueue_frame_chain(__rte_unused void *qat_sym_qp,
		__rte_unused struct rte_cryptodev_sym_session *session,
		__rte_unused rte_iova_t data_iova,
		__rte_unused uint32_t cipher_ofs,
		__rte_unused uint32_t cipher_len,
		__rte_unused uint32_t auth_ofs,
		__rte_unused uint32_t auth_len,
		__rte_unused struct rte_crypto_vec *sgl,
		__rte_unused uint32_t n_sgl_vecs,
		__rte_unused uint8_t *iv, __rte_unused rte_iova_t digest_iova,
		__rte_unused uint8_t is_first,
		__rte_unused uint8_t is_last, __rte_unused void *frame)
{
	/* TODO: implement the body */
	return 0;
}

int
qat_sym_enqueue_frame_cipher(__rte_unused void *qat_sym_qp,
		__rte_unused struct rte_cryptodev_sym_session *session,
		__rte_unused rte_iova_t data_iova,
		__rte_unused uint32_t cipher_ofs,
		__rte_unused uint32_t cipher_len,
		__rte_unused struct rte_crypto_vec *sgl,
		__rte_unused uint32_t n_sgl_vecs,
		__rte_unused uint8_t *iv,
		__rte_unused uint8_t is_first,
		__rte_unused uint8_t is_last, __rte_unused void *frame)
{
	/* TODO: implement the body */
	return 0;
}

int
qat_sym_enqueue_frame_auth(__rte_unused void *qat_sym_qp,
		__rte_unused struct rte_cryptodev_sym_session *session,
		__rte_unused rte_iova_t data_iova,
		__rte_unused uint32_t auth_ofs,
		__rte_unused uint32_t auth_len,
		__rte_unused struct rte_crypto_vec *sgl,
		__rte_unused uint32_t n_sgl_vecs,
		__rte_unused uint8_t *iv, __rte_unused rte_iova_t digest_iova,
		__rte_unused uint8_t is_first,
		__rte_unused uint8_t is_last, __rte_unused void *frame)
{
	/* TODO: implement the body */
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
	struct icp_qat_fw_comn_resp *resp, *resp1, *resp2, *resp3;
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

	status += element_interval;

	/* fetch 4 messages in a loop */
	for (i = 1; i < n_elts - 4; i += 4) {
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

	for (; i < n_elts; i++) {
		resp = get_rx_queue_message_at_index(rx_queue, head, 0);
		if (qat_is_rx_msg_ok(resp))
			*status = element_status_success;
		else {
			*status = element_status_error;
			n_fail--;
		}
		status += element_interval;
		head = (head + rx_queue->msg_size * 4) & rx_queue->modulo_mask;
	}

	/* update queue pair head */
	rx_queue->head = (rx_queue->head + i * rx_queue->msg_size) &
			rx_queue->modulo_mask;
	rx_queue->nb_processed_responses += i;
	qp->dequeued += i;
	qp->stats.dequeued_count += i;
	if (rx_queue->nb_processed_responses > QAT_CSR_HEAD_WRITE_THRESH)
		rxq_free_desc(qp, rx_queue);

	return n_fail + n_fail1 + n_fail2 + n_fail3;
}

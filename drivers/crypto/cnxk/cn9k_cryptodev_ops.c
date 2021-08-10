/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_cryptodev.h>
#include <cryptodev_pmd.h>

#include "cn9k_cryptodev.h"
#include "cn9k_cryptodev_ops.h"
#include "cnxk_ae.h"
#include "cnxk_cryptodev.h"
#include "cnxk_cryptodev_ops.h"
#include "cnxk_se.h"

static __rte_always_inline int __rte_hot
cn9k_cpt_sym_inst_fill(struct cnxk_cpt_qp *qp, struct rte_crypto_op *op,
		       struct cnxk_se_sess *sess,
		       struct cpt_inflight_req *infl_req,
		       struct cpt_inst_s *inst)
{
	uint64_t cpt_op;
	int ret = -1;

	cpt_op = sess->cpt_op;

	if (cpt_op & ROC_SE_OP_CIPHER_MASK)
		ret = fill_fc_params(op, sess, &qp->meta_info, infl_req, inst);
	else
		ret = fill_digest_params(op, sess, &qp->meta_info, infl_req,
					 inst);

	return ret;
}

static inline struct cnxk_se_sess *
cn9k_cpt_sym_temp_sess_create(struct cnxk_cpt_qp *qp, struct rte_crypto_op *op)
{
	const int driver_id = cn9k_cryptodev_driver_id;
	struct rte_crypto_sym_op *sym_op = op->sym;
	struct rte_cryptodev_sym_session *sess;
	struct cnxk_se_sess *priv;
	int ret;

	/* Create temporary session */
	sess = rte_cryptodev_sym_session_create(qp->sess_mp);
	if (sess == NULL)
		return NULL;

	ret = sym_session_configure(qp->lf.roc_cpt, driver_id, sym_op->xform,
				    sess, qp->sess_mp_priv);
	if (ret)
		goto sess_put;

	priv = get_sym_session_private_data(sess, driver_id);

	sym_op->session = sess;

	return priv;

sess_put:
	rte_mempool_put(qp->sess_mp, sess);
	return NULL;
}

static uint16_t
cn9k_cpt_enqueue_burst(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct cpt_inflight_req *infl_req;
	struct rte_crypto_asym_op *asym_op;
	struct rte_crypto_sym_op *sym_op;
	uint16_t nb_allowed, count = 0;
	struct cnxk_cpt_qp *qp = qptr;
	struct pending_queue *pend_q;
	struct rte_crypto_op *op;
	struct cpt_inst_s inst;
	uint64_t lmt_status;
	uint64_t lmtline;
	uint64_t io_addr;
	int ret;

	pend_q = &qp->pend_q;

	lmtline = qp->lmtline.lmt_base;
	io_addr = qp->lmtline.io_addr;

	inst.w0.u64 = 0;
	inst.w2.u64 = 0;
	inst.w3.u64 = 0;

	nb_allowed = qp->lf.nb_desc - pend_q->pending_count;
	nb_ops = RTE_MIN(nb_ops, nb_allowed);

	for (count = 0; count < nb_ops; count++) {
		op = ops[count];
		infl_req = &pend_q->req_queue[pend_q->enq_tail];
		infl_req->op_flags = 0;

		if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			struct cnxk_se_sess *sess;

			if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
				sym_op = op->sym;
				sess = get_sym_session_private_data(
					sym_op->session,
					cn9k_cryptodev_driver_id);
				ret = cn9k_cpt_sym_inst_fill(qp, op, sess,
							     infl_req, &inst);
			} else {
				sess = cn9k_cpt_sym_temp_sess_create(qp, op);
				if (unlikely(sess == NULL)) {
					plt_dp_err(
						"Could not create temp session");
					break;
				}

				ret = cn9k_cpt_sym_inst_fill(qp, op, sess,
							     infl_req, &inst);
				if (unlikely(ret)) {
					sym_session_clear(
						cn9k_cryptodev_driver_id,
						op->sym->session);
					rte_mempool_put(qp->sess_mp,
							op->sym->session);
				}
			}
			inst.w7.u64 = sess->cpt_inst_w7;
		} else if (op->type == RTE_CRYPTO_OP_TYPE_ASYMMETRIC) {
			struct cnxk_ae_sess *sess;

			ret = -EINVAL;
			if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
				asym_op = op->asym;
				sess = get_asym_session_private_data(
					asym_op->session,
					cn9k_cryptodev_driver_id);
				ret = cnxk_ae_enqueue(qp, op, infl_req, &inst,
						      sess);
				inst.w7.u64 = sess->cpt_inst_w7;
			}
		} else {
			plt_dp_err("Unsupported op type");
			break;
		}

		if (unlikely(ret)) {
			plt_dp_err("Could not process op: %p", op);
			break;
		}

		infl_req->cop = op;

		infl_req->res.cn9k.compcode = CPT_COMP_NOT_DONE;
		inst.res_addr = (uint64_t)&infl_req->res;

		do {
			/* Copy CPT command to LMTLINE */
			memcpy((void *)lmtline, &inst, sizeof(inst));

			/*
			 * Make sure compiler does not reorder memcpy and ldeor.
			 * LMTST transactions are always flushed from the write
			 * buffer immediately, a DMB is not required to push out
			 * LMTSTs.
			 */
			rte_io_wmb();
			lmt_status = roc_lmt_submit_ldeor(io_addr);
		} while (lmt_status == 0);

		MOD_INC(pend_q->enq_tail, qp->lf.nb_desc);
	}

	pend_q->pending_count += count;
	pend_q->time_out = rte_get_timer_cycles() +
			   DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();

	return count;
}

static inline void
cn9k_cpt_dequeue_post_process(struct cnxk_cpt_qp *qp, struct rte_crypto_op *cop,
			      struct cpt_inflight_req *infl_req)
{
	struct cpt_cn9k_res_s *res = (struct cpt_cn9k_res_s *)&infl_req->res;
	unsigned int sz;

	if (likely(res->compcode == CPT_COMP_GOOD)) {
		if (unlikely(res->uc_compcode)) {
			if (res->uc_compcode == ROC_SE_ERR_GC_ICV_MISCOMPARE)
				cop->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
			else
				cop->status = RTE_CRYPTO_OP_STATUS_ERROR;

			plt_dp_info("Request failed with microcode error");
			plt_dp_info("MC completion code 0x%x",
				    res->uc_compcode);
			goto temp_sess_free;
		}

		cop->status = RTE_CRYPTO_OP_STATUS_SUCCESS;
		if (cop->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			/* Verify authentication data if required */
			if (unlikely(infl_req->op_flags &
				     CPT_OP_FLAGS_AUTH_VERIFY)) {
				uintptr_t *rsp = infl_req->mdata;
				compl_auth_verify(cop, (uint8_t *)rsp[0],
						  rsp[1]);
			}
		} else if (cop->type == RTE_CRYPTO_OP_TYPE_ASYMMETRIC) {
			struct rte_crypto_asym_op *op = cop->asym;
			uintptr_t *mdata = infl_req->mdata;
			struct cnxk_ae_sess *sess;

			sess = get_asym_session_private_data(
				op->session, cn9k_cryptodev_driver_id);

			cnxk_ae_post_process(cop, sess, (uint8_t *)mdata[0]);
		}
	} else {
		cop->status = RTE_CRYPTO_OP_STATUS_ERROR;
		plt_dp_info("HW completion code 0x%x", res->compcode);

		switch (res->compcode) {
		case CPT_COMP_INSTERR:
			plt_dp_err("Request failed with instruction error");
			break;
		case CPT_COMP_FAULT:
			plt_dp_err("Request failed with DMA fault");
			break;
		case CPT_COMP_HWERR:
			plt_dp_err("Request failed with hardware error");
			break;
		default:
			plt_dp_err(
				"Request failed with unknown completion code");
		}
	}

temp_sess_free:
	if (unlikely(cop->sess_type == RTE_CRYPTO_OP_SESSIONLESS)) {
		if (cop->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			sym_session_clear(cn9k_cryptodev_driver_id,
					  cop->sym->session);
			sz = rte_cryptodev_sym_get_existing_header_session_size(
				cop->sym->session);
			memset(cop->sym->session, 0, sz);
			rte_mempool_put(qp->sess_mp, cop->sym->session);
			cop->sym->session = NULL;
		}
	}
}

static uint16_t
cn9k_cpt_dequeue_burst(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct cnxk_cpt_qp *qp = qptr;
	struct pending_queue *pend_q;
	struct cpt_inflight_req *infl_req;
	struct cpt_cn9k_res_s *res;
	struct rte_crypto_op *cop;
	uint32_t pq_deq_head;
	int i;

	pend_q = &qp->pend_q;

	nb_ops = RTE_MIN(nb_ops, pend_q->pending_count);

	pq_deq_head = pend_q->deq_head;

	for (i = 0; i < nb_ops; i++) {
		infl_req = &pend_q->req_queue[pq_deq_head];

		res = (struct cpt_cn9k_res_s *)&infl_req->res;

		if (unlikely(res->compcode == CPT_COMP_NOT_DONE)) {
			if (unlikely(rte_get_timer_cycles() >
				     pend_q->time_out)) {
				plt_err("Request timed out");
				pend_q->time_out = rte_get_timer_cycles() +
						   DEFAULT_COMMAND_TIMEOUT *
							   rte_get_timer_hz();
			}
			break;
		}

		MOD_INC(pq_deq_head, qp->lf.nb_desc);

		cop = infl_req->cop;

		ops[i] = cop;

		cn9k_cpt_dequeue_post_process(qp, cop, infl_req);

		if (unlikely(infl_req->op_flags & CPT_OP_FLAGS_METABUF))
			rte_mempool_put(qp->meta_info.pool, infl_req->mdata);
	}

	pend_q->pending_count -= i;
	pend_q->deq_head = pq_deq_head;

	return i;
}
void
cn9k_cpt_set_enqdeq_fns(struct rte_cryptodev *dev)
{
	dev->enqueue_burst = cn9k_cpt_enqueue_burst;
	dev->dequeue_burst = cn9k_cpt_dequeue_burst;

	rte_mb();
}

static void
cn9k_cpt_dev_info_get(struct rte_cryptodev *dev,
		      struct rte_cryptodev_info *info)
{
	if (info != NULL) {
		cnxk_cpt_dev_info_get(dev, info);
		info->driver_id = cn9k_cryptodev_driver_id;
	}
}

struct rte_cryptodev_ops cn9k_cpt_ops = {
	/* Device control ops */
	.dev_configure = cnxk_cpt_dev_config,
	.dev_start = cnxk_cpt_dev_start,
	.dev_stop = cnxk_cpt_dev_stop,
	.dev_close = cnxk_cpt_dev_close,
	.dev_infos_get = cn9k_cpt_dev_info_get,

	.stats_get = NULL,
	.stats_reset = NULL,
	.queue_pair_setup = cnxk_cpt_queue_pair_setup,
	.queue_pair_release = cnxk_cpt_queue_pair_release,

	/* Symmetric crypto ops */
	.sym_session_get_size = cnxk_cpt_sym_session_get_size,
	.sym_session_configure = cnxk_cpt_sym_session_configure,
	.sym_session_clear = cnxk_cpt_sym_session_clear,

	/* Asymmetric crypto ops */
	.asym_session_get_size = cnxk_ae_session_size_get,
	.asym_session_configure = cnxk_ae_session_cfg,
	.asym_session_clear = cnxk_ae_session_clear,

};

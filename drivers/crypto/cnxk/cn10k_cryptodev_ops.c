/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>

#include "cn10k_cryptodev.h"
#include "cn10k_cryptodev_ops.h"
#include "cnxk_cryptodev.h"
#include "cnxk_cryptodev_ops.h"
#include "cnxk_se.h"

static inline struct cnxk_se_sess *
cn10k_cpt_sym_temp_sess_create(struct cnxk_cpt_qp *qp, struct rte_crypto_op *op)
{
	const int driver_id = cn10k_cryptodev_driver_id;
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

static __rte_always_inline int __rte_hot
cpt_sym_inst_fill(struct cnxk_cpt_qp *qp, struct rte_crypto_op *op,
		  struct cnxk_se_sess *sess, struct cpt_inflight_req *infl_req,
		  struct cpt_inst_s *inst)
{
	uint64_t cpt_op;
	int ret;

	cpt_op = sess->cpt_op;

	if (cpt_op & ROC_SE_OP_CIPHER_MASK)
		ret = fill_fc_params(op, sess, &qp->meta_info, infl_req, inst);

	return ret;
}

static inline int
cn10k_cpt_fill_inst(struct cnxk_cpt_qp *qp, struct rte_crypto_op *ops[],
		    struct cpt_inst_s inst[], struct cpt_inflight_req *infl_req)
{
	struct rte_crypto_sym_op *sym_op;
	struct cnxk_se_sess *sess;
	struct rte_crypto_op *op;
	uint64_t w7;
	int ret;

	op = ops[0];

	inst[0].w0.u64 = 0;
	inst[0].w2.u64 = 0;
	inst[0].w3.u64 = 0;

	sym_op = op->sym;

	if (op->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
		if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
			sess = get_sym_session_private_data(
				sym_op->session, cn10k_cryptodev_driver_id);
			ret = cpt_sym_inst_fill(qp, op, sess, infl_req,
						&inst[0]);
			if (unlikely(ret))
				return 0;
			w7 = sess->cpt_inst_w7;
		} else {
			sess = cn10k_cpt_sym_temp_sess_create(qp, op);
			if (unlikely(sess == NULL)) {
				CPT_LOG_DP_ERR("Could not create temp session");
				return 0;
			}

			ret = cpt_sym_inst_fill(qp, op, sess, infl_req,
						&inst[0]);
			if (unlikely(ret)) {
				sym_session_clear(cn10k_cryptodev_driver_id,
						  op->sym->session);
				rte_mempool_put(qp->sess_mp, op->sym->session);
				return 0;
			}
			w7 = sess->cpt_inst_w7;
		}
	} else {
		CPT_LOG_DP_ERR("Unsupported op type");
		return 0;
	}

	inst[0].res_addr = (uint64_t)&infl_req->res;
	infl_req->res.cn10k.compcode = CPT_COMP_NOT_DONE;
	infl_req->cop = op;

	inst[0].w7.u64 = w7;

	return 1;
}

#define PKTS_PER_LOOP	32
#define PKTS_PER_STEORL 16

static uint16_t
cn10k_cpt_enqueue_burst(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	uint64_t lmt_base, lmt_arg, io_addr;
	struct cpt_inflight_req *infl_req;
	uint16_t nb_allowed, count = 0;
	struct cnxk_cpt_qp *qp = qptr;
	struct pending_queue *pend_q;
	struct cpt_inst_s *inst;
	uint16_t lmt_id;
	int ret, i;

	pend_q = &qp->pend_q;

	nb_allowed = qp->lf.nb_desc - pend_q->pending_count;
	nb_ops = RTE_MIN(nb_ops, nb_allowed);

	if (unlikely(nb_ops == 0))
		return 0;

	lmt_base = qp->lmtline.lmt_base;
	io_addr = qp->lmtline.io_addr;

	ROC_LMT_BASE_ID_GET(lmt_base, lmt_id);
	inst = (struct cpt_inst_s *)lmt_base;

again:
	for (i = 0; i < RTE_MIN(PKTS_PER_LOOP, nb_ops); i++) {
		infl_req = &pend_q->req_queue[pend_q->enq_tail];
		infl_req->op_flags = 0;

		ret = cn10k_cpt_fill_inst(qp, ops + i, &inst[2 * i], infl_req);
		if (unlikely(ret != 1)) {
			CPT_LOG_DP_ERR("Could not process op: %p", ops + i);
			if (i == 0)
				goto update_pending;
			break;
		}

		MOD_INC(pend_q->enq_tail, qp->lf.nb_desc);
	}

	if (i > PKTS_PER_STEORL) {
		lmt_arg = ROC_CN10K_CPT_LMT_ARG | (PKTS_PER_STEORL - 1) << 12 |
			  (uint64_t)lmt_id;
		roc_lmt_submit_steorl(lmt_arg, io_addr);
		lmt_arg = ROC_CN10K_CPT_LMT_ARG |
			  (i - PKTS_PER_STEORL - 1) << 12 |
			  (uint64_t)(lmt_id + PKTS_PER_STEORL);
		roc_lmt_submit_steorl(lmt_arg, io_addr);
	} else {
		lmt_arg = ROC_CN10K_CPT_LMT_ARG | (i - 1) << 12 |
			  (uint64_t)lmt_id;
		roc_lmt_submit_steorl(lmt_arg, io_addr);
	}

	rte_io_wmb();

	if (nb_ops - i > 0 && i == PKTS_PER_LOOP) {
		nb_ops -= i;
		ops += i;
		count += i;
		goto again;
	}

update_pending:
	pend_q->pending_count += count + i;

	pend_q->time_out = rte_get_timer_cycles() +
			   DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();

	return count + i;
}

static inline void
cn10k_cpt_dequeue_post_process(struct cnxk_cpt_qp *qp,
			       struct rte_crypto_op *cop,
			       struct cpt_inflight_req *infl_req)
{
	struct cpt_cn10k_res_s *res = (struct cpt_cn10k_res_s *)&infl_req->res;
	unsigned int sz;

	if (likely(res->compcode == CPT_COMP_GOOD ||
		   res->compcode == CPT_COMP_WARN)) {
		if (unlikely(res->uc_compcode)) {
			cop->status = RTE_CRYPTO_OP_STATUS_ERROR;

			CPT_LOG_DP_DEBUG("Request failed with microcode error");
			CPT_LOG_DP_DEBUG("MC completion code 0x%x",
					 res->uc_compcode);
			goto temp_sess_free;
		}

		cop->status = RTE_CRYPTO_OP_STATUS_SUCCESS;
	} else {
		cop->status = RTE_CRYPTO_OP_STATUS_ERROR;
		CPT_LOG_DP_DEBUG("HW completion code 0x%x", res->compcode);

		switch (res->compcode) {
		case CPT_COMP_INSTERR:
			CPT_LOG_DP_ERR("Request failed with instruction error");
			break;
		case CPT_COMP_FAULT:
			CPT_LOG_DP_ERR("Request failed with DMA fault");
			break;
		case CPT_COMP_HWERR:
			CPT_LOG_DP_ERR("Request failed with hardware error");
			break;
		default:
			CPT_LOG_DP_ERR(
				"Request failed with unknown completion code");
		}
	}

temp_sess_free:
	if (unlikely(cop->sess_type == RTE_CRYPTO_OP_SESSIONLESS)) {
		if (cop->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			sym_session_clear(cn10k_cryptodev_driver_id,
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
cn10k_cpt_dequeue_burst(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	struct cpt_inflight_req *infl_req;
	struct cnxk_cpt_qp *qp = qptr;
	struct pending_queue *pend_q;
	struct cpt_cn10k_res_s *res;
	struct rte_crypto_op *cop;
	int i, nb_pending;

	pend_q = &qp->pend_q;

	nb_pending = pend_q->pending_count;

	if (nb_ops > nb_pending)
		nb_ops = nb_pending;

	for (i = 0; i < nb_ops; i++) {
		infl_req = &pend_q->req_queue[pend_q->deq_head];

		res = (struct cpt_cn10k_res_s *)&infl_req->res;

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

		MOD_INC(pend_q->deq_head, qp->lf.nb_desc);

		cop = infl_req->cop;

		ops[i] = cop;

		cn10k_cpt_dequeue_post_process(qp, cop, infl_req);

		if (unlikely(infl_req->op_flags & CPT_OP_FLAGS_METABUF))
			rte_mempool_put(qp->meta_info.pool, infl_req->mdata);
	}

	pend_q->pending_count -= i;

	return i;
}

void
cn10k_cpt_set_enqdeq_fns(struct rte_cryptodev *dev)
{
	dev->enqueue_burst = cn10k_cpt_enqueue_burst;
	dev->dequeue_burst = cn10k_cpt_dequeue_burst;

	rte_mb();
}

static void
cn10k_cpt_dev_info_get(struct rte_cryptodev *dev,
		       struct rte_cryptodev_info *info)
{
	if (info != NULL) {
		cnxk_cpt_dev_info_get(dev, info);
		info->driver_id = cn10k_cryptodev_driver_id;
	}
}

struct rte_cryptodev_ops cn10k_cpt_ops = {
	/* Device control ops */
	.dev_configure = cnxk_cpt_dev_config,
	.dev_start = cnxk_cpt_dev_start,
	.dev_stop = cnxk_cpt_dev_stop,
	.dev_close = cnxk_cpt_dev_close,
	.dev_infos_get = cn10k_cpt_dev_info_get,

	.stats_get = NULL,
	.stats_reset = NULL,
	.queue_pair_setup = cnxk_cpt_queue_pair_setup,
	.queue_pair_release = cnxk_cpt_queue_pair_release,

	/* Symmetric crypto ops */
	.sym_session_get_size = cnxk_cpt_sym_session_get_size,
	.sym_session_configure = cnxk_cpt_sym_session_configure,
	.sym_session_clear = cnxk_cpt_sym_session_clear,

	/* Asymmetric crypto ops */
	.asym_session_get_size = NULL,
	.asym_session_configure = NULL,
	.asym_session_clear = NULL,

};

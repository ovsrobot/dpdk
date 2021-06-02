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
	RTE_SET_USED(qp);
	RTE_SET_USED(op);
	RTE_SET_USED(sess);
	RTE_SET_USED(infl_req);
	RTE_SET_USED(inst);

	return -ENOTSUP;
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

void
cn10k_cpt_set_enqdeq_fns(struct rte_cryptodev *dev)
{
	dev->enqueue_burst = cn10k_cpt_enqueue_burst;

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

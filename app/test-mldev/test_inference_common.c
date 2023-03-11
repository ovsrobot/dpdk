/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include <errno.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_mldev.h>

#include "ml_common.h"
#include "test_inference_common.h"

/* Enqueue inference requests with burst size equal to 1 */
static int
ml_enqueue_single(void *arg)
{
	struct test_inference *t = ml_test_priv((struct ml_test *)arg);
	struct ml_request *req = NULL;
	struct rte_ml_op *op = NULL;
	struct ml_core_args *args;
	uint64_t model_enq = 0;
	uint32_t burst_enq;
	uint32_t lcore_id;
	uint16_t fid;
	int ret;

	lcore_id = rte_lcore_id();
	args = &t->args[lcore_id];
	model_enq = 0;

	if (args->nb_reqs == 0)
		return 0;

next_rep:
	fid = args->start_fid;

next_model:
	ret = rte_mempool_get(t->op_pool, (void **)&op);
	if (ret != 0)
		goto next_model;

retry:
	ret = rte_mempool_get(t->model[fid].io_pool, (void **)&req);
	if (ret != 0)
		goto retry;

	op->model_id = t->model[fid].id;
	op->nb_batches = t->model[fid].nb_batches;
	op->mempool = t->op_pool;

	op->input.addr = req->input;
	op->input.length = t->model[fid].inp_qsize;
	op->input.next = NULL;

	op->output.addr = req->output;
	op->output.length = t->model[fid].out_qsize;
	op->output.next = NULL;

	op->user_ptr = req;
	req->niters++;
	req->fid = fid;

enqueue_req:
	burst_enq = rte_ml_enqueue_burst(t->cmn.opt->dev_id, args->qp_id, &op, 1);
	if (burst_enq == 0)
		goto enqueue_req;

	fid++;
	if (likely(fid <= args->end_fid))
		goto next_model;

	model_enq++;
	if (likely(model_enq < args->nb_reqs))
		goto next_rep;

	return 0;
}

/* Dequeue inference requests with burst size equal to 1 */
static int
ml_dequeue_single(void *arg)
{
	struct test_inference *t = ml_test_priv((struct ml_test *)arg);
	struct rte_ml_op_error error;
	struct rte_ml_op *op = NULL;
	struct ml_core_args *args;
	struct ml_request *req;
	uint64_t total_deq = 0;
	uint8_t nb_filelist;
	uint32_t burst_deq;
	uint32_t lcore_id;

	lcore_id = rte_lcore_id();
	args = &t->args[lcore_id];
	nb_filelist = args->end_fid - args->start_fid + 1;

	if (args->nb_reqs == 0)
		return 0;

dequeue_req:
	burst_deq = rte_ml_dequeue_burst(t->cmn.opt->dev_id, args->qp_id, &op, 1);

	if (likely(burst_deq == 1)) {
		total_deq += burst_deq;
		if (unlikely(op->status == RTE_ML_OP_STATUS_ERROR)) {
			rte_ml_op_error_get(t->cmn.opt->dev_id, op, &error);
			ml_err("error_code = 0x%" PRIx64 ", error_message = %s\n", error.errcode,
			       error.message);
			t->error_count[lcore_id]++;
		}
		req = (struct ml_request *)op->user_ptr;
		rte_mempool_put(t->model[req->fid].io_pool, req);
		rte_mempool_put(t->op_pool, op);
	}

	if (likely(total_deq < args->nb_reqs * nb_filelist))
		goto dequeue_req;

	return 0;
}

/* Enqueue inference requests with burst size greater than 1 */
static int
ml_enqueue_burst(void *arg)
{
	struct test_inference *t = ml_test_priv((struct ml_test *)arg);
	struct ml_core_args *args;
	uint16_t ops_count;
	uint64_t model_enq;
	uint16_t burst_enq;
	uint32_t lcore_id;
	uint16_t pending;
	uint16_t idx;
	uint16_t fid;
	uint16_t i;
	int ret;

	lcore_id = rte_lcore_id();
	args = &t->args[lcore_id];
	model_enq = 0;

	if (args->nb_reqs == 0)
		return 0;

next_rep:
	fid = args->start_fid;

next_model:
	ops_count = RTE_MIN(t->cmn.opt->burst_size, args->nb_reqs - model_enq);
	ret = rte_mempool_get_bulk(t->op_pool, (void **)args->enq_ops, ops_count);
	if (ret != 0)
		goto next_model;

retry:
	ret = rte_mempool_get_bulk(t->model[fid].io_pool, (void **)args->reqs, ops_count);
	if (ret != 0)
		goto retry;

	for (i = 0; i < ops_count; i++) {
		args->enq_ops[i]->model_id = t->model[fid].id;
		args->enq_ops[i]->nb_batches = t->model[fid].nb_batches;
		args->enq_ops[i]->mempool = t->op_pool;

		args->enq_ops[i]->input.addr = args->reqs[i]->input;
		args->enq_ops[i]->input.length = t->model[fid].inp_qsize;
		args->enq_ops[i]->input.next = NULL;

		args->enq_ops[i]->output.addr = args->reqs[i]->output;
		args->enq_ops[i]->output.length = t->model[fid].out_qsize;
		args->enq_ops[i]->output.next = NULL;

		args->enq_ops[i]->user_ptr = args->reqs[i];
		args->reqs[i]->niters++;
		args->reqs[i]->fid = fid;
	}

	idx = 0;
	pending = ops_count;

enqueue_reqs:
	burst_enq =
		rte_ml_enqueue_burst(t->cmn.opt->dev_id, args->qp_id, &args->enq_ops[idx], pending);
	pending = pending - burst_enq;

	if (pending > 0) {
		idx = idx + burst_enq;
		goto enqueue_reqs;
	}

	fid++;
	if (fid <= args->end_fid)
		goto next_model;

	model_enq = model_enq + ops_count;
	if (model_enq < args->nb_reqs)
		goto next_rep;

	return 0;
}

/* Dequeue inference requests with burst size greater than 1 */
static int
ml_dequeue_burst(void *arg)
{
	struct test_inference *t = ml_test_priv((struct ml_test *)arg);
	struct rte_ml_op_error error;
	struct ml_core_args *args;
	struct ml_request *req;
	uint64_t total_deq = 0;
	uint16_t burst_deq = 0;
	uint8_t nb_filelist;
	uint32_t lcore_id;
	uint32_t i;

	lcore_id = rte_lcore_id();
	args = &t->args[lcore_id];
	nb_filelist = args->end_fid - args->start_fid + 1;

	if (args->nb_reqs == 0)
		return 0;

dequeue_burst:
	burst_deq = rte_ml_dequeue_burst(t->cmn.opt->dev_id, args->qp_id, args->deq_ops,
					 t->cmn.opt->burst_size);

	if (likely(burst_deq > 0)) {
		total_deq += burst_deq;

		for (i = 0; i < burst_deq; i++) {
			if (unlikely(args->deq_ops[i]->status == RTE_ML_OP_STATUS_ERROR)) {
				rte_ml_op_error_get(t->cmn.opt->dev_id, args->deq_ops[i], &error);
				ml_err("error_code = 0x%" PRIx64 ", error_message = %s\n",
				       error.errcode, error.message);
				t->error_count[lcore_id]++;
			}
			req = (struct ml_request *)args->deq_ops[i]->user_ptr;
			if (req != NULL)
				rte_mempool_put(t->model[req->fid].io_pool, req);
		}
		rte_mempool_put_bulk(t->op_pool, (void *)args->deq_ops, burst_deq);
	}

	if (total_deq < args->nb_reqs * nb_filelist)
		goto dequeue_burst;

	return 0;
}

bool
test_inference_cap_check(struct ml_options *opt)
{
	struct rte_ml_dev_info dev_info;

	if (!ml_test_cap_check(opt))
		return false;

	rte_ml_dev_info_get(opt->dev_id, &dev_info);

	if (opt->queue_pairs > dev_info.max_queue_pairs) {
		ml_err("Insufficient capabilities: queue_pairs = %u, max_queue_pairs = %u",
		       opt->queue_pairs, dev_info.max_queue_pairs);
		return false;
	}

	if (opt->queue_size > dev_info.max_desc) {
		ml_err("Insufficient capabilities: queue_size = %u, max_desc = %u", opt->queue_size,
		       dev_info.max_desc);
		return false;
	}

	if (opt->nb_filelist > dev_info.max_models) {
		ml_err("Insufficient capabilities:  Filelist count exceeded device limit, count = %u (max limit = %u)",
		       opt->nb_filelist, dev_info.max_models);
		return false;
	}

	return true;
}

int
test_inference_opt_check(struct ml_options *opt)
{
	uint32_t i;
	int ret;

	/* check common opts */
	ret = ml_test_opt_check(opt);
	if (ret != 0)
		return ret;

	/* check file availability */
	for (i = 0; i < opt->nb_filelist; i++) {
		if (access(opt->filelist[i].model, F_OK) == -1) {
			ml_err("Model file not accessible: id = %u, file = %s", i,
			       opt->filelist[i].model);
			return -ENOENT;
		}

		if (access(opt->filelist[i].input, F_OK) == -1) {
			ml_err("Input file not accessible: id = %u, file = %s", i,
			       opt->filelist[i].input);
			return -ENOENT;
		}
	}

	if (opt->repetitions == 0) {
		ml_err("Invalid option, repetitions = %" PRIu64 "\n", opt->repetitions);
		return -EINVAL;
	}

	if (opt->burst_size == 0) {
		ml_err("Invalid option, burst_size = %u\n", opt->burst_size);
		return -EINVAL;
	}

	if (opt->burst_size > ML_TEST_MAX_POOL_SIZE) {
		ml_err("Invalid option, burst_size = %u (> max supported = %d)\n", opt->burst_size,
		       ML_TEST_MAX_POOL_SIZE);
		return -EINVAL;
	}

	if (opt->queue_pairs == 0) {
		ml_err("Invalid option, queue_pairs = %u\n", opt->queue_pairs);
		return -EINVAL;
	}

	if (opt->queue_size == 0) {
		ml_err("Invalid option, queue_size = %u\n", opt->queue_size);
		return -EINVAL;
	}

	/* check number of available lcores. */
	if (rte_lcore_count() < (uint32_t)(opt->queue_pairs * 2 + 1)) {
		ml_err("Insufficient lcores = %u\n", rte_lcore_count());
		ml_err("Minimum lcores required to create %u queue-pairs = %u\n", opt->queue_pairs,
		       (opt->queue_pairs * 2 + 1));
		return -EINVAL;
	}

	return 0;
}

void
test_inference_opt_dump(struct ml_options *opt)
{
	uint32_t i;

	/* dump common opts */
	ml_test_opt_dump(opt);

	/* dump test opts */
	ml_dump("repetitions", "%" PRIu64, opt->repetitions);
	ml_dump("burst_size", "%u", opt->burst_size);
	ml_dump("queue_pairs", "%u", opt->queue_pairs);
	ml_dump("queue_size", "%u", opt->queue_size);

	if (opt->batches == 0)
		ml_dump("batches", "%u (default)", opt->batches);
	else
		ml_dump("batches", "%u", opt->batches);

	ml_dump_begin("filelist");
	for (i = 0; i < opt->nb_filelist; i++) {
		ml_dump_list("model", i, opt->filelist[i].model);
		ml_dump_list("input", i, opt->filelist[i].input);
		ml_dump_list("output", i, opt->filelist[i].output);
	}
	ml_dump_end;
}

int
test_inference_setup(struct ml_test *test, struct ml_options *opt)
{
	struct test_inference *t;
	void *test_inference;
	uint32_t lcore_id;
	int ret = 0;
	uint32_t i;

	test_inference = rte_zmalloc_socket(test->name, sizeof(struct test_inference),
					    RTE_CACHE_LINE_SIZE, opt->socket_id);
	if (test_inference == NULL) {
		ml_err("failed to allocate memory for test_model");
		ret = -ENOMEM;
		goto error;
	}
	test->test_priv = test_inference;
	t = ml_test_priv(test);

	t->nb_used = 0;
	t->cmn.result = ML_TEST_FAILED;
	t->cmn.opt = opt;
	memset(t->error_count, 0, RTE_MAX_LCORE * sizeof(uint64_t));

	/* get device info */
	ret = rte_ml_dev_info_get(opt->dev_id, &t->cmn.dev_info);
	if (ret < 0) {
		ml_err("failed to get device info");
		goto error;
	}

	if (opt->burst_size == 1) {
		t->enqueue = ml_enqueue_single;
		t->dequeue = ml_dequeue_single;
	} else {
		t->enqueue = ml_enqueue_burst;
		t->dequeue = ml_dequeue_burst;
	}

	/* set model initial state */
	for (i = 0; i < opt->nb_filelist; i++)
		t->model[i].state = MODEL_INITIAL;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		t->args[lcore_id].enq_ops = rte_zmalloc_socket(
			"ml_test_enq_ops", opt->burst_size * sizeof(struct rte_ml_op *),
			RTE_CACHE_LINE_SIZE, opt->socket_id);
		t->args[lcore_id].deq_ops = rte_zmalloc_socket(
			"ml_test_deq_ops", opt->burst_size * sizeof(struct rte_ml_op *),
			RTE_CACHE_LINE_SIZE, opt->socket_id);
		t->args[lcore_id].reqs = rte_zmalloc_socket(
			"ml_test_requests", opt->burst_size * sizeof(struct ml_request *),
			RTE_CACHE_LINE_SIZE, opt->socket_id);
	}

	return 0;

error:
	if (test_inference != NULL)
		rte_free(test_inference);

	return ret;
}

void
test_inference_destroy(struct ml_test *test, struct ml_options *opt)
{
	struct test_inference *t;

	RTE_SET_USED(opt);

	t = ml_test_priv(test);
	if (t != NULL)
		rte_free(t);
}

int
ml_inference_mldev_setup(struct ml_test *test, struct ml_options *opt)
{
	struct rte_ml_dev_qp_conf qp_conf;
	struct test_inference *t;
	uint16_t qp_id;
	int ret;

	t = ml_test_priv(test);

	RTE_SET_USED(t);

	ret = ml_test_device_configure(test, opt);
	if (ret != 0)
		return ret;

	/* setup queue pairs */
	qp_conf.nb_desc = opt->queue_size;
	qp_conf.cb = NULL;

	for (qp_id = 0; qp_id < opt->queue_pairs; qp_id++) {
		qp_conf.nb_desc = opt->queue_size;
		qp_conf.cb = NULL;

		ret = rte_ml_dev_queue_pair_setup(opt->dev_id, qp_id, &qp_conf, opt->socket_id);
		if (ret != 0) {
			ml_err("Failed to setup ml device queue-pair, dev_id = %d, qp_id = %u\n",
			       opt->dev_id, qp_id);
			return ret;
		}
	}

	ret = ml_test_device_start(test, opt);
	if (ret != 0)
		goto error;

	return 0;

error:
	ml_test_device_close(test, opt);

	return ret;
}

int
ml_inference_mldev_destroy(struct ml_test *test, struct ml_options *opt)
{
	int ret;

	ret = ml_test_device_stop(test, opt);
	if (ret != 0)
		goto error;

	ret = ml_test_device_close(test, opt);
	if (ret != 0)
		return ret;

	return 0;

error:
	ml_test_device_close(test, opt);

	return ret;
}

/* Callback for IO pool create. This function would compute the fields of ml_request
 * structure and prepare the quantized input data.
 */
static void
ml_request_initialize(struct rte_mempool *mp, void *opaque, void *obj, unsigned int obj_idx)
{
	struct test_inference *t = ml_test_priv((struct ml_test *)opaque);
	struct ml_request *req = (struct ml_request *)obj;

	RTE_SET_USED(mp);
	RTE_SET_USED(obj_idx);

	req->input = (uint8_t *)obj +
		     RTE_ALIGN_CEIL(sizeof(struct ml_request), t->cmn.dev_info.min_align_size);
	req->output = req->input +
		      RTE_ALIGN_CEIL(t->model[t->fid].inp_qsize, t->cmn.dev_info.min_align_size);
	req->niters = 0;

	/* quantize data */
	rte_ml_io_quantize(t->cmn.opt->dev_id, t->model[t->fid].id, t->model[t->fid].nb_batches,
			   t->model[t->fid].input, req->input);
}

int
ml_inference_iomem_setup(struct ml_test *test, struct ml_options *opt, uint16_t fid)
{
	struct test_inference *t = ml_test_priv(test);
	char mz_name[RTE_MEMZONE_NAMESIZE];
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	const struct rte_memzone *mz;
	uint64_t nb_buffers;
	uint32_t buff_size;
	uint32_t mz_size;
	uint32_t fsize;
	FILE *fp;
	int ret;

	/* get input buffer size */
	ret = rte_ml_io_input_size_get(opt->dev_id, t->model[fid].id, t->model[fid].nb_batches,
				       &t->model[fid].inp_qsize, &t->model[fid].inp_dsize);
	if (ret != 0) {
		ml_err("Failed to get input size, model : %s\n", opt->filelist[fid].model);
		return ret;
	}

	/* get output buffer size */
	ret = rte_ml_io_output_size_get(opt->dev_id, t->model[fid].id, t->model[fid].nb_batches,
					&t->model[fid].out_qsize, &t->model[fid].out_dsize);
	if (ret != 0) {
		ml_err("Failed to get input size, model : %s\n", opt->filelist[fid].model);
		return ret;
	}

	/* allocate buffer for user data */
	mz_size = t->model[fid].inp_dsize + t->model[fid].out_dsize;
	sprintf(mz_name, "ml_user_data_%d", fid);
	mz = rte_memzone_reserve(mz_name, mz_size, opt->socket_id, 0);
	if (mz == NULL) {
		ml_err("Memzone allocation failed for ml_user_data\n");
		ret = -ENOMEM;
		goto error;
	}

	t->model[fid].input = mz->addr;
	t->model[fid].output = t->model[fid].input + t->model[fid].inp_dsize;

	/* load input file */
	fp = fopen(opt->filelist[fid].input, "r");
	if (fp == NULL) {
		ml_err("Failed to open input file : %s\n", opt->filelist[fid].input);
		ret = -errno;
		goto error;
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (fsize != t->model[fid].inp_dsize) {
		ml_err("Invalid input file, size = %u (expected size = %" PRIu64 ")\n", fsize,
		       t->model[fid].inp_dsize);
		ret = -EINVAL;
		fclose(fp);
		goto error;
	}

	if (fread(t->model[fid].input, 1, t->model[fid].inp_dsize, fp) != t->model[fid].inp_dsize) {
		ml_err("Failed to read input file : %s\n", opt->filelist[fid].input);
		ret = -errno;
		fclose(fp);
		goto error;
	}
	fclose(fp);

	/* create mempool for quantized input and output buffers. ml_request_initialize is
	 * used as a callback for object creation.
	 */
	buff_size = RTE_ALIGN_CEIL(sizeof(struct ml_request), t->cmn.dev_info.min_align_size) +
		    RTE_ALIGN_CEIL(t->model[fid].inp_qsize, t->cmn.dev_info.min_align_size) +
		    RTE_ALIGN_CEIL(t->model[fid].out_qsize, t->cmn.dev_info.min_align_size);
	nb_buffers = RTE_MIN((uint64_t)ML_TEST_MAX_POOL_SIZE, opt->repetitions);

	t->fid = fid;
	sprintf(mp_name, "ml_io_pool_%d", fid);
	t->model[fid].io_pool = rte_mempool_create(mp_name, nb_buffers, buff_size, 0, 0, NULL, NULL,
						   ml_request_initialize, test, opt->socket_id, 0);
	if (t->model[fid].io_pool == NULL) {
		ml_err("Failed to create io pool : %s\n", "ml_io_pool");
		ret = -ENOMEM;
		goto error;
	}

	return 0;

error:
	if (mz != NULL)
		rte_memzone_free(mz);

	if (t->model[fid].io_pool != NULL) {
		rte_mempool_free(t->model[fid].io_pool);
		t->model[fid].io_pool = NULL;
	}

	return ret;
}

void
ml_inference_iomem_destroy(struct ml_test *test, struct ml_options *opt, uint16_t fid)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	const struct rte_memzone *mz;
	struct rte_mempool *mp;

	RTE_SET_USED(test);
	RTE_SET_USED(opt);

	/* release user data memzone */
	sprintf(mz_name, "ml_user_data_%d", fid);
	mz = rte_memzone_lookup(mz_name);
	if (mz != NULL)
		rte_memzone_free(mz);

	/* destroy io pool */
	sprintf(mp_name, "ml_io_pool_%d", fid);
	mp = rte_mempool_lookup(mp_name);
	if (mp != NULL)
		rte_mempool_free(mp);
}

int
ml_inference_mem_setup(struct ml_test *test, struct ml_options *opt)
{
	struct test_inference *t = ml_test_priv(test);

	/* create op pool */
	t->op_pool = rte_ml_op_pool_create("ml_test_op_pool", ML_TEST_MAX_POOL_SIZE, 0, 0,
					   opt->socket_id);
	if (t->op_pool == NULL) {
		ml_err("Failed to create op pool : %s\n", "ml_op_pool");
		return -ENOMEM;
	}

	return 0;
}

void
ml_inference_mem_destroy(struct ml_test *test, struct ml_options *opt)
{
	struct test_inference *t = ml_test_priv(test);

	RTE_SET_USED(opt);

	/* release op pool */
	if (t->op_pool != NULL)
		rte_mempool_free(t->op_pool);
}

/* Callback for mempool object iteration. This call would dequantize output data. */
static void
ml_request_finish(struct rte_mempool *mp, void *opaque, void *obj, unsigned int obj_idx)
{
	struct test_inference *t = ml_test_priv((struct ml_test *)opaque);
	struct ml_request *req = (struct ml_request *)obj;
	struct ml_model *model = &t->model[req->fid];

	RTE_SET_USED(mp);
	RTE_SET_USED(obj_idx);

	if (req->niters == 0)
		return;

	t->nb_used++;
	rte_ml_io_dequantize(t->cmn.opt->dev_id, model->id, t->model[req->fid].nb_batches,
			     req->output, model->output);
}

int
ml_inference_result(struct ml_test *test, struct ml_options *opt, uint16_t fid)
{
	struct test_inference *t = ml_test_priv(test);
	uint64_t error_count = 0;
	uint32_t i;

	RTE_SET_USED(opt);

	/* check for errors */
	for (i = 0; i < RTE_MAX_LCORE; i++)
		error_count += t->error_count[i];

	rte_mempool_obj_iter(t->model[fid].io_pool, ml_request_finish, test);

	if ((t->nb_used > 0) && (error_count == 0))
		t->cmn.result = ML_TEST_SUCCESS;
	else
		t->cmn.result = ML_TEST_FAILED;

	return t->cmn.result;
}

int
ml_inference_launch_cores(struct ml_test *test, struct ml_options *opt, uint16_t start_fid,
			  uint16_t end_fid)
{
	struct test_inference *t = ml_test_priv(test);
	uint32_t lcore_id;
	uint32_t nb_reqs;
	uint32_t id = 0;
	uint32_t qp_id;

	nb_reqs = opt->repetitions / opt->queue_pairs;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (id >= opt->queue_pairs * 2)
			break;

		qp_id = id / 2;
		t->args[lcore_id].qp_id = qp_id;
		t->args[lcore_id].nb_reqs = nb_reqs;
		if (qp_id == 0)
			t->args[lcore_id].nb_reqs += opt->repetitions - nb_reqs * opt->queue_pairs;

		if (t->args[lcore_id].nb_reqs == 0) {
			id++;
			break;
		}

		t->args[lcore_id].start_fid = start_fid;
		t->args[lcore_id].end_fid = end_fid;

		if (id % 2 == 0)
			rte_eal_remote_launch(t->enqueue, test, lcore_id);
		else
			rte_eal_remote_launch(t->dequeue, test, lcore_id);

		id++;
	}

	return 0;
}

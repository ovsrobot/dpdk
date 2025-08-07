/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <eal_export.h>
#include <rte_log.h>
#include <rte_errno.h>

#include "bpf_impl.h"

static struct rte_bpf *
bpf_copy(const struct rte_bpf_prm *prm, uint8_t *buf)
{
	struct rte_bpf *bpf;
	size_t xsz =  prm->nb_xsym * sizeof(prm->xsym[0]);
	size_t insz = prm->nb_ins * sizeof(prm->ins[0]);
	size_t bsz = sizeof(bpf[0]);
	size_t sz = insz + xsz + bsz;

	bpf = (void *)buf;
	bpf->sz = sz;
	memcpy(&bpf->prm, prm, sizeof(bpf->prm));

	if (xsz > 0)
		memcpy(buf + bsz, prm->xsym, xsz);
	memcpy(buf + bsz + xsz, prm->ins, insz);

	bpf->prm.xsym = (void *)(buf + bsz);
	bpf->prm.ins = (void *)(buf + bsz + xsz);

	return bpf;
}

static size_t
bpf_buf_size(const struct rte_bpf_prm *prm)
{
	size_t xsz =  prm->nb_xsym * sizeof(prm->xsym[0]);
	size_t insz = prm->nb_ins * sizeof(prm->ins[0]);
	size_t bsz = sizeof(struct rte_bpf);

	return insz + xsz + bsz;
}

static struct rte_bpf *
bpf_load(const struct rte_bpf_prm *prm)
{
	void *buf;
	size_t len = bpf_buf_size(prm);

	buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		return NULL;

	return bpf_copy(prm, buf);
}

/*
 * Check that user provided external symbol.
 */
static int
bpf_check_xsym(const struct rte_bpf_xsym *xsym)
{
	uint32_t i;

	if (xsym->name == NULL)
		return -EINVAL;

	if (xsym->type == RTE_BPF_XTYPE_VAR) {
		if (xsym->var.desc.type == RTE_BPF_ARG_UNDEF)
			return -EINVAL;
	} else if (xsym->type == RTE_BPF_XTYPE_FUNC) {

		if (xsym->func.nb_args > EBPF_FUNC_MAX_ARGS)
			return -EINVAL;

		/* check function arguments */
		for (i = 0; i != xsym->func.nb_args; i++) {
			if (xsym->func.args[i].type == RTE_BPF_ARG_UNDEF)
				return -EINVAL;
		}

		/* check return value info */
		if (xsym->func.ret.type != RTE_BPF_ARG_UNDEF &&
				xsym->func.ret.size == 0)
			return -EINVAL;
	} else
		return -EINVAL;

	return 0;
}

RTE_EXPORT_SYMBOL(rte_bpf_load)
struct rte_bpf *
rte_bpf_load(const struct rte_bpf_prm *prm)
{
	struct rte_bpf *bpf;
	int32_t rc;
	uint32_t i;

	if (prm == NULL || prm->ins == NULL ||
			(prm->nb_xsym != 0 && prm->xsym == NULL)) {
		rte_errno = EINVAL;
		return NULL;
	}

	rc = 0;
	for (i = 0; i != prm->nb_xsym && rc == 0; i++)
		rc = bpf_check_xsym(prm->xsym + i);

	if (rc != 0) {
		rte_errno = -rc;
		RTE_BPF_LOG_LINE(ERR, "%s: %d-th xsym is invalid", __func__, i);
		return NULL;
	}

	bpf = bpf_load(prm);
	if (bpf == NULL) {
		rte_errno = ENOMEM;
		return NULL;
	}

	rc = __rte_bpf_validate(bpf);
	if (rc == 0) {
		__rte_bpf_jit(bpf);
		if (mprotect(bpf, bpf->sz, PROT_READ) != 0)
			rc = -ENOMEM;
	}

	if (rc != 0) {
		rte_bpf_destroy(bpf);
		rte_errno = -rc;
		return NULL;
	}

	return bpf;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_bpf_buf_size, 25.11)
ssize_t
rte_bpf_buf_size(const struct rte_bpf_prm *prm)
{
	int rc = 0;
	uint32_t i;

	if (prm == NULL || prm->ins == NULL ||
	    (prm->nb_xsym != 0 && prm->xsym == NULL)) {
		rte_errno = EINVAL;
		return -1;
	}

	for (i = 0; i != prm->nb_xsym && rc == 0; i++)
		rc = bpf_check_xsym(prm->xsym + i);

	if (rc != 0) {
		rte_errno = -rc;
		RTE_BPF_LOG_LINE(ERR, "%s: %d-th xsym is invalid", __func__, i);
		return -1;
	}

	return bpf_buf_size(prm);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_bpf_buf_load, 25.11)
struct rte_bpf *
rte_bpf_buf_load(const struct rte_bpf_prm *prm, void *buf, size_t len)
{
	struct rte_bpf *bpf;
	int32_t rc;
	uint32_t i;

	if (prm == NULL || prm->ins == NULL ||
	    (prm->nb_xsym != 0 && prm->xsym == NULL)) {
		rte_errno = EINVAL;
		return NULL;
	}

	rc = 0;
	for (i = 0; i != prm->nb_xsym && rc == 0; i++)
		rc = bpf_check_xsym(prm->xsym + i);

	if (rc != 0) {
		rte_errno = -rc;
		RTE_BPF_LOG_LINE(ERR, "%s: %d-th xsym is invalid", __func__, i);
		return NULL;
	}

	size_t sz = bpf_buf_size(prm);
	if (len < sz) {
		rte_errno = -EINVAL;
		RTE_BPF_LOG_LINE(ERR, "%s: len %zu < required %zu",
				 __func__, len, sz);
		return NULL;
	}

	bpf = bpf_copy(prm, buf);
	rc = __rte_bpf_validate(bpf);
	if (rc != 0) {
		rte_errno = -rc;
		return NULL;
	}

	/* This bpf code is in non protected memory it can not use JIT  */
	return bpf;
}

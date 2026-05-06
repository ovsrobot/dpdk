/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

#include <errno.h>
#include <stdio.h>

#include <eal_export.h>
#include <rte_errno.h>
#include <rte_flow.h>
#include <rte_malloc.h>

#include "flow_compile_priv.h"
#include "rte_flow_compile.h"

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile, 26.07)
struct rte_flow_compile *
rte_flow_compile(const char *str, char *errbuf)
{
	if (str == NULL || errbuf == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}
	errbuf[0] = '\0';

	struct rte_flow_compile *out =
		rte_zmalloc("rte_flow_compile", sizeof(*out), 0);
	if (out == NULL) {
		snprintf(errbuf, RTE_FLOW_COMPILE_ERRBUF_SIZE,
			 "0:0: out of memory");
		rte_errno = ENOMEM;
		return NULL;
	}

	struct flow_compile_ctx cc = {
		.src = str,
		.cur = str,
		.line = 1,
		.col  = 1,
		.errbuf = errbuf,
		.out = out,
	};

	if (flow_compile_parse(&cc, out) < 0) {
		rte_flow_compile_free(out);
		return NULL;
	}
	return out;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile_free, 26.07)
void
rte_flow_compile_free(struct rte_flow_compile *fc)
{
	if (fc == NULL)
		return;
	if (fc->pattern != NULL) {
		for (unsigned int i = 0; i < fc->npattern; i++) {
			/* Cast through uintptr_t to drop the API's
			 * const without -Wcast-qual; the parser owns
			 * these allocations.
			 */
			rte_free((void *)(uintptr_t)fc->pattern[i].spec);
			rte_free((void *)(uintptr_t)fc->pattern[i].mask);
			rte_free((void *)(uintptr_t)fc->pattern[i].last);
		}
		rte_free(fc->pattern);
	}
	if (fc->actions != NULL) {
		for (unsigned int i = 0; i < fc->nactions; i++)
			rte_free((void *)(uintptr_t)fc->actions[i].conf);
		rte_free(fc->actions);
	}
	rte_free(fc);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile_attr, 26.07)
const struct rte_flow_attr *
rte_flow_compile_attr(const struct rte_flow_compile *fc)
{
	return fc != NULL ? &fc->attr : NULL;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile_pattern, 26.07)
const struct rte_flow_item *
rte_flow_compile_pattern(const struct rte_flow_compile *fc, unsigned int *n)
{
	if (fc == NULL)
		return NULL;
	if (n != NULL)
		*n = fc->npattern;
	return fc->pattern;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile_actions, 26.07)
const struct rte_flow_action *
rte_flow_compile_actions(const struct rte_flow_compile *fc, unsigned int *n)
{
	if (fc == NULL)
		return NULL;
	if (n != NULL)
		*n = fc->nactions;
	return fc->actions;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile_validate, 26.07)
int
rte_flow_compile_validate(uint16_t port_id, const struct rte_flow_compile *fc,
			  struct rte_flow_error *error)
{
	if (fc == NULL)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"compiled rule is NULL");
	return rte_flow_validate(port_id, &fc->attr, fc->pattern, fc->actions,
				 error);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_compile_create, 26.07)
struct rte_flow *
rte_flow_compile_create(uint16_t port_id, const struct rte_flow_compile *fc,
			struct rte_flow_error *error)
{
	if (fc == NULL) {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"compiled rule is NULL");
		return NULL;
	}
	return rte_flow_create(port_id, &fc->attr, fc->pattern, fc->actions,
			       error);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Stephen Hemminger
 */

/*
 * Stub flow operations for the net_null PMD.
 *
 * These ops provide a realistic-but-minimal implementation of
 * rte_flow_ops that can be used for API-layer testing.  Every
 * operation walks its input, performs basic structural validation,
 * and then rejects the request with the most specific error type
 * and message it can produce.  This exercises the full flow-API
 * code path (port lookup → ops dispatch → PMD callback → error
 * propagation) without requiring any hardware.
 *
 * Summary of behaviour:
 *
 *   validate  – walks pattern + actions; rejects each unsupported
 *               item/action with RTE_FLOW_ERROR_TYPE_ITEM or
 *               _ACTION, pointing `cause` at the offending element.
 *               A structurally valid rule whose items are all VOID/END
 *               and whose actions are all VOID/END gets rejected at
 *               the attribute level (no ingress+egress+transfer) or
 *               with a generic "no resources" if nothing else applies.
 *
 *   create    – calls validate, then returns NULL (never creates).
 *
 *   destroy   – returns -ENOENT (no flows exist).
 *
 *   flush     – succeeds (there are no flows to flush).
 *
 *   query     – returns -ENOTSUP (no queryable actions).
 *
 *   isolate   – returns -ENOTSUP (isolation not supported).
 */

#include <errno.h>
#include <string.h>

#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_flow_driver.h>

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/*
 * Walk the pattern array and reject the first item that is not
 * VOID or END.  Return 0 if nothing objectionable was found
 * (all items are VOID/END), or -rte_errno on failure.
 */
static int
null_flow_validate_pattern(const struct rte_flow_item pattern[],
			   struct rte_flow_error *error)
{
	const struct rte_flow_item *item;

	if (pattern == NULL)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ITEM_NUM,
			NULL, "NULL pattern");

	for (item = pattern;
	     item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->type == RTE_FLOW_ITEM_TYPE_VOID)
			continue;

		/* Any real match item is unsupported. */
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ITEM,
			item,
			"null PMD does not support pattern items");
	}

	return 0; /* only VOID + END */
}

/*
 * Walk the action array and reject the first action that is not
 * VOID or END.  Same semantics as above.
 */
static int
null_flow_validate_actions(const struct rte_flow_action actions[],
			   struct rte_flow_error *error)
{
	const struct rte_flow_action *action;

	if (actions == NULL)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION_NUM,
			NULL, "NULL action list");

	for (action = actions;
	     action->type != RTE_FLOW_ACTION_TYPE_END; action++) {
		if (action->type == RTE_FLOW_ACTION_TYPE_VOID)
			continue;

		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ACTION,
			action,
			"null PMD does not support flow actions");
	}

	return 0; /* only VOID + END */
}

/* --------------------------------------------------------------------------
 * Flow ops callbacks
 * -------------------------------------------------------------------------- */

static int
null_flow_validate(struct rte_eth_dev *dev __rte_unused,
		   const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[],
		   const struct rte_flow_action actions[],
		   struct rte_flow_error *error)
{
	int ret;

	/* ---- attribute checks ---- */
	if (attr == NULL)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ATTR,
			NULL, "NULL attributes");

	if (!attr->ingress && !attr->egress && !attr->transfer)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ATTR,
			attr,
			"at least one of ingress/egress/transfer "
			"must be set");

	if (attr->transfer)
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER,
			attr,
			"transfer attribute not supported");

	if (attr->group > 0)
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
			attr,
			"only group 0 is supported");

	if (attr->priority > 0)
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
			attr,
			"only priority 0 is supported");

	/* ---- pattern checks ---- */
	ret = null_flow_validate_pattern(pattern, error);
	if (ret)
		return ret;

	/* ---- action checks ---- */
	ret = null_flow_validate_actions(actions, error);
	if (ret)
		return ret;

	/*
	 * If we get here, the rule is structurally valid but contains
	 * nothing but VOID items and VOID actions — reject generically.
	 */
	return rte_flow_error_set(error, ENOTSUP,
		RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
		NULL,
		"null PMD cannot offload any flow rules");
}

static struct rte_flow *
null_flow_create(struct rte_eth_dev *dev,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item pattern[],
		 const struct rte_flow_action actions[],
		 struct rte_flow_error *error)
{
	null_flow_validate(dev, attr, pattern, actions, error);
	return NULL;
}

static int
null_flow_destroy(struct rte_eth_dev *dev __rte_unused,
		  struct rte_flow *flow __rte_unused,
		  struct rte_flow_error *error)
{
	return rte_flow_error_set(error, ENOENT,
		RTE_FLOW_ERROR_TYPE_HANDLE,
		flow,
		"no flow rules exist on null PMD");
}

static int
null_flow_flush(struct rte_eth_dev *dev __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	/* Nothing to flush — success. */
	return 0;
}

static int
null_flow_query(struct rte_eth_dev *dev __rte_unused,
		struct rte_flow *flow __rte_unused,
		const struct rte_flow_action *action __rte_unused,
		void *data __rte_unused,
		struct rte_flow_error *error)
{
	return rte_flow_error_set(error, ENOTSUP,
		RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
		NULL,
		"null PMD does not support flow queries");
}

static int
null_flow_isolate(struct rte_eth_dev *dev __rte_unused,
		  int set __rte_unused,
		  struct rte_flow_error *error)
{
	return rte_flow_error_set(error, ENOTSUP,
		RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
		NULL,
		"null PMD does not support flow isolation");
}

/* --------------------------------------------------------------------------
 * Public ops structure — referenced by rte_eth_null.c
 * -------------------------------------------------------------------------- */

const struct rte_flow_ops null_flow_ops = {
	.validate = null_flow_validate,
	.create   = null_flow_create,
	.destroy  = null_flow_destroy,
	.flush    = null_flow_flush,
	.query    = null_flow_query,
	.isolate  = null_flow_isolate,
};

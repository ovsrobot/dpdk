/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Intel Corporation
 */

#ifndef _COMMON_INTEL_FLOW_CHECK_H_
#define _COMMON_INTEL_FLOW_CHECK_H_

#include <bus_pci_driver.h>
#include <ethdev_driver.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common attr and action validation code for Intel drivers.
 */

/**
 * Maximum number of actions that can be stored in a parsed action list.
 */
#define CI_FLOW_PARSED_ACTIONS_MAX 4

/* Actions that are reasonably expected to have a conf structure */
static const enum rte_flow_action_type need_conf[] = {
	RTE_FLOW_ACTION_TYPE_QUEUE,
	RTE_FLOW_ACTION_TYPE_RSS,
	RTE_FLOW_ACTION_TYPE_VF,
	RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR,
	RTE_FLOW_ACTION_TYPE_COUNT,
	RTE_FLOW_ACTION_TYPE_MARK,
	RTE_FLOW_ACTION_TYPE_SECURITY,
	RTE_FLOW_ACTION_TYPE_END
};

/**
 * Is action type in this list of action types?
 */
__rte_internal
static inline bool
ci_flow_action_type_in_list(const enum rte_flow_action_type type,
		const enum rte_flow_action_type list[])
{
	size_t i = 0;
	while (list[i] != RTE_FLOW_ACTION_TYPE_END) {
		if (type == list[i])
			return true;
		i++;
	}
	return false;
}

/* Forward declarations */
struct ci_flow_actions;
struct ci_flow_actions_check_param;
struct ci_flow_attr_check_param;

/**
 * Driver-specific action list validation callback.
 *
 * Performs driver-specific validation of action parameter list.
 * Called after all actions have been parsed and added to the list,
 * allowing validation based on the complete action set.
 *
 * @param actions
 *   The complete list of parsed actions (for context-dependent validation).
 * @param driver_ctx
 *   Opaque driver context (e.g., adapter/queue configuration).
 * @param error
 *   Pointer to rte_flow_error for reporting failures.
 * @return
 *   0 on success, negative errno on failure.
 */
typedef int (*ci_flow_actions_check_fn)(const struct ci_flow_actions *actions,
		const struct ci_flow_actions_check_param *param,
		struct rte_flow_error *error);

/**
 * List of actions that we know we've validated.
 */
struct ci_flow_actions {
	/* Number of actions in the list. */
	uint8_t count;
	/* Parsed actions array. */
	struct rte_flow_action const *actions[CI_FLOW_PARSED_ACTIONS_MAX];
};

/**
 * Parameters for action list validation. Any element can be NULL/0 as checks are only performed
 * against constraints specified.
 */
struct ci_flow_actions_check_param {
	/**
	 * Driver-specific context pointer (e.g., adapter/queue configuration). Can be NULL.
	 */
	void *driver_ctx;
	/**
	 * Driver-specific action list validation callback. Can be NULL.
	 */
	ci_flow_actions_check_fn check;
	/**
	 * Allowed action types for this parse parameter. Must be terminated with
	 * RTE_FLOW_ACTION_TYPE_END. Can be NULL.
	 */
	const enum rte_flow_action_type *allowed_types;
	size_t max_actions;                 /**< Maximum number of actions allowed. */
};

static inline int
__flow_action_check_rss(const struct rte_flow_action_rss *rss, struct rte_flow_error *error)
{
	size_t q, q_num = rss->queue_num;
	if ((q_num == 0) == (rss->queue == NULL)) {
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss,
			"If queue number is specified, queue array must also be specified");
	}
	for (q = 1; q < q_num; q++) {
		uint16_t qi = rss->queue[q];
		if (rss->queue[q - 1] + 1 != qi) {
			return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss,
				"RSS queues must be contiguous");
		}
	}
	/* either we have both key and key length, or we have neither */
	if ((rss->key_len == 0) != (rss->key == NULL)) {
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss,
			"If RSS key is specified, key length must also be specified");
	}
	return 0;
}

static inline int
__flow_action_check_generic(const struct rte_flow_action *action,
		const struct ci_flow_actions_check_param *param,
		struct rte_flow_error *error)
{
	/* is this action in our allowed list? */
	if (param != NULL && param->allowed_types != NULL &&
			!ci_flow_action_type_in_list(action->type, param->allowed_types)) {
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				action, "Unsupported action");
	}
	/* do we need to validate presence of conf? */
	if (ci_flow_action_type_in_list(action->type, need_conf)) {
		if (action->conf == NULL) {
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ACTION_CONF, action,
						  "Action requires configuration");
		}
	}

	/* type-specific validation */
	switch (action->type) {
	case RTE_FLOW_ACTION_TYPE_RSS:
	{
		const struct rte_flow_action_rss *rss =
				(const struct rte_flow_action_rss *)action->conf;
		if (__flow_action_check_rss(rss, error) < 0)
			return -rte_errno;
		break;
	}
	default:
		/* no specific validation */
		break;
	}

	return 0;
}

/**
 * Validate and parse a list of rte_flow_action into a parsed action list.
 *
 * @param actions pointer to array of rte_flow_action, terminated by RTE_FLOW_ACTION_TYPE_END
 * @param param pointer to ci_flow_actions_check_param structure (can be NULL)
 * @param parsed_actions pointer to ci_flow_actions structure to store parsed actions
 * @param error pointer to rte_flow_error structure for error reporting
 *
 * @return 0 on success, negative errno on failure.
 */
__rte_internal
static inline int
ci_flow_check_actions(const struct rte_flow_action *actions,
	const struct ci_flow_actions_check_param *param,
	struct ci_flow_actions *parsed_actions,
	struct rte_flow_error *error)
{
	size_t i = 0;

	if (actions == NULL) {
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				NULL, "Missing actions");
	}

	/* reset the list */
	*parsed_actions = (struct ci_flow_actions){0};

	while (actions[i].type != RTE_FLOW_ACTION_TYPE_END) {
		const struct rte_flow_action *action = &actions[i++];

		/* skip VOID actions */
		if (action->type == RTE_FLOW_ACTION_TYPE_VOID)
			continue;

		/* generic validation for actions - this will check against param as well */
		if (__flow_action_check_generic(action, param, error) < 0)
			return -rte_errno;

		/* add action to the list */
		if (parsed_actions->count >= RTE_DIM(parsed_actions->actions)) {
			return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
							action, "Too many actions");
		}
		/* user may have specified a maximum number of actions */
		if (param != NULL && param->max_actions != 0 &&
		    parsed_actions->count >= param->max_actions) {
			return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
							action, "Too many actions");
		}
		parsed_actions->actions[parsed_actions->count++] = action;
	}

	/* now, call into user validation if specified */
	if (param != NULL && param->check != NULL) {
		if (param->check(parsed_actions, param, error) < 0)
			return -rte_errno;
	}
	/* if we didn't parse anything, valid action list is empty */
	return parsed_actions->count == 0 ? -EINVAL : 0;
}

/**
 * Parameter structure for attr check.
 */
struct ci_flow_attr_check_param {
	bool allow_priority; /**< True if priority attribute is allowed. */
	bool allow_transfer; /**< True if transfer attribute is allowed. */
	bool allow_group;    /**< True if group attribute is allowed. */
	bool expect_egress;  /**< True if egress attribute is expected. */
};

/**
 * Validate rte_flow_attr structure against specified constraints.
 *
 * @param attr Pointer to rte_flow_attr structure to validate.
 * @param attr_param Pointer to ci_flow_attr_check_param structure specifying constraints.
 * @param error Pointer to rte_flow_error structure for error reporting.
 *
 * @return 0 on success, negative errno on failure.
 */
__rte_internal
static inline int
ci_flow_check_attr(const struct rte_flow_attr *attr,
		const struct ci_flow_attr_check_param *attr_param,
		struct rte_flow_error *error)
{
	if (attr == NULL) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR, attr,
					  "NULL attribute");
	}

	/* Direction must be either ingress or egress */
	if (attr->ingress == attr->egress) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR, attr,
					  "Either ingress or egress must be set");
	}

	/* Expect ingress by default */
	if (attr->egress && (attr_param == NULL || !attr_param->expect_egress)) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, attr,
					  "Egress not supported");
	}

	/* May not be supported */
	if (attr->transfer && (attr_param == NULL || !attr_param->allow_transfer)) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER, attr,
					  "Transfer not supported");
	}

	/* May not be supported */
	if (attr->group && (attr_param == NULL || !attr_param->allow_group)) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR_GROUP, attr,
					  "Group not supported");
	}

	/* May not be supported */
	if (attr->priority && (attr_param == NULL || !attr_param->allow_priority)) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, attr,
					  "Priority not supported");
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_INTEL_FLOW_CHECK_H_ */

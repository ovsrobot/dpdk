/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_geneve.h>
#include <rte_gre.h>
#include <rte_gtp.h>
#include <rte_mpls.h>
#include <rte_string_fns.h>
#include <rte_vxlan.h>
#include <rte_ip.h>
#include <rte_flow.h>
#include <rte_flow_parser.h>

#include "testpmd.h"
#include "flow_parser.h"

static struct rte_port *
parser_port_get(uint16_t port_id)
{
	if (port_id_is_invalid(port_id, DISABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return NULL;
	return &ports[port_id];
}

static struct port_flow *
parser_flow_by_index(struct rte_port *port, unsigned int index)
{
	struct port_flow *pf = port->flow_list;

	while (pf && index--)
		pf = pf->next;
	return pf;
}

static struct port_template *
parser_template_by_index(struct port_template *list, unsigned int index)
{
	struct port_template *pt = list;

	while (pt && index--)
		pt = pt->next;
	return pt;
}

static struct port_table *
parser_table_by_index(struct port_table *list, unsigned int index)
{
	struct port_table *pt = list;

	while (pt && index--)
		pt = pt->next;
	return pt;
}

static const struct tunnel_ops *
parser_tunnel_convert(const struct rte_flow_parser_tunnel_ops *src,
		      struct tunnel_ops *dst)
{
	if (!src)
		return NULL;
	memset(dst, 0, sizeof(*dst));
	dst->id = src->id;
	strlcpy(dst->type, src->type, sizeof(dst->type));
	dst->enabled = src->enabled;
	dst->actions = src->actions;
	dst->items = src->items;
	return dst;
}

static int
parser_port_validate(uint16_t port_id)
{
	return port_id_is_invalid(port_id, DISABLED_WARN);
}

static uint16_t
parser_flow_rule_count(uint16_t port_id)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	if (!port)
		return 0;
	for (struct port_flow *pf = port->flow_list; pf; pf = pf->next)
		count++;
	return count;
}

static int
parser_flow_rule_id_get(uint16_t port_id, unsigned int index,
			uint64_t *rule_id)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_flow *pf;

	if (!port || !rule_id)
		return -ENOENT;
	pf = parser_flow_by_index(port, index);
	if (!pf)
		return -ENOENT;
	*rule_id = pf->id;
	return 0;
}

static uint16_t
parser_pattern_template_count(uint16_t port_id)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	if (!port)
		return 0;
	for (struct port_template *pt = port->pattern_templ_list;
	     pt;
	     pt = pt->next)
		count++;
	return count;
}

static int
parser_pattern_template_id_get(uint16_t port_id, unsigned int index,
			       uint32_t *template_id)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_template *pt;

	if (!port || !template_id)
		return -ENOENT;
	pt = parser_template_by_index(port->pattern_templ_list, index);
	if (!pt)
		return -ENOENT;
	*template_id = pt->id;
	return 0;
}

static uint16_t
parser_actions_template_count(uint16_t port_id)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	if (!port)
		return 0;
	for (struct port_template *pt = port->actions_templ_list;
	     pt;
	     pt = pt->next)
		count++;
	return count;
}

static int
parser_actions_template_id_get(uint16_t port_id, unsigned int index,
			       uint32_t *template_id)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_template *pt;

	if (!port || !template_id)
		return -ENOENT;
	pt = parser_template_by_index(port->actions_templ_list, index);
	if (!pt)
		return -ENOENT;
	*template_id = pt->id;
	return 0;
}

static uint16_t
parser_table_count(uint16_t port_id)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	if (!port)
		return 0;
	for (struct port_table *pt = port->table_list; pt; pt = pt->next)
		count++;
	return count;
}

static int
parser_table_id_get(uint16_t port_id, unsigned int index,
		    uint32_t *table_id)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_table *pt;

	if (!port || !table_id)
		return -ENOENT;
	pt = parser_table_by_index(port->table_list, index);
	if (!pt)
		return -ENOENT;
	*table_id = pt->id;
	return 0;
}

static uint16_t
parser_queue_count(uint16_t port_id)
{
	struct rte_port *port = parser_port_get(port_id);

	if (!port)
		return 0;
	return port->queue_nb;
}

static uint16_t
parser_rss_queue_count(uint16_t port_id)
{
	struct rte_port *port = parser_port_get(port_id);

	if (!port)
		return 0;
	return port->queue_nb ? port->queue_nb : port->dev_info.max_rx_queues;
}

static struct rte_flow_template_table *
parser_table_get(uint16_t port_id, uint32_t table_id)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_table *pt;

	if (!port)
		return NULL;
	for (pt = port->table_list; pt; pt = pt->next)
		if (pt->id == table_id)
			return pt->table;
	return NULL;
}

static struct rte_flow_action_handle *
parser_action_handle_get(uint16_t port_id, uint32_t action_id)
{
	return port_action_handle_get_by_id(port_id, action_id);
}

static struct rte_flow_meter_profile *
parser_meter_profile_get(uint16_t port_id, uint32_t profile_id)
{
	return port_meter_profile_get_by_id(port_id, profile_id);
}

static struct rte_flow_meter_policy *
parser_meter_policy_get(uint16_t port_id, uint32_t policy_id)
{
	return port_meter_policy_get_by_id(port_id, policy_id);
}

static struct rte_flow_item_flex_handle *
parser_flex_handle_get(uint16_t port_id, uint16_t flex_id)
{
	struct flex_item *fp;

	if (port_id >= RTE_MAX_ETHPORTS || flex_id >= FLEX_MAX_PARSERS_NUM)
		return NULL;
	fp = flex_items[port_id][flex_id];
	return fp ? fp->flex_handle : NULL;
}

static int
parser_flex_pattern_get(uint16_t pattern_id,
			const struct rte_flow_item_flex **spec,
			const struct rte_flow_item_flex **mask)
{
	if (pattern_id >= FLEX_MAX_PATTERNS_NUM || !spec || !mask)
		return -ENOENT;
	*spec = &flex_patterns[pattern_id].spec;
	*mask = &flex_patterns[pattern_id].mask;
	return 0;
}

static uint16_t
parser_verbose_level_get(void)
{
	return verbose_level;
}

static void
parser_queue_group_set_miss_actions(uint16_t port_id,
				    const struct rte_flow_attr *attr,
				    const struct rte_flow_action actions[])
{
	port_queue_group_set_miss_actions(port_id, attr, actions);
}

static void
parser_flow_get_info(uint16_t port_id)
{
	port_flow_get_info(port_id);
}

static void
parser_flow_configure(uint16_t port_id,
		      const struct rte_flow_port_attr *port_attr,
		      uint32_t nb_queue,
		      const struct rte_flow_queue_attr *queue_attr)
{
	port_flow_configure(port_id, port_attr, (uint16_t)nb_queue, queue_attr);
}

static void
parser_flow_pattern_template_create(uint16_t port_id, uint32_t id,
				    const struct rte_flow_pattern_template_attr *attr,
				    const struct rte_flow_item pattern[])
{
	port_flow_pattern_template_create(port_id, id, attr, pattern);
}

static void
parser_flow_pattern_template_destroy(uint16_t port_id,
				     uint32_t nb_id,
				     const uint32_t id[])
{
	port_flow_pattern_template_destroy(port_id, nb_id, id);
}

static void
parser_flow_actions_template_create(uint16_t port_id, uint32_t id,
				    const struct rte_flow_actions_template_attr *attr,
				    const struct rte_flow_action actions[],
				    const struct rte_flow_action masks[])
{
	port_flow_actions_template_create(port_id, id, attr, actions, masks);
}

static void
parser_flow_actions_template_destroy(uint16_t port_id,
				     uint32_t nb_id,
				     const uint32_t id[])
{
	port_flow_actions_template_destroy(port_id, nb_id, id);
}

static void
parser_flow_template_table_create(uint16_t port_id, uint32_t table_id,
				  const struct rte_flow_template_table_attr *attr,
				  uint32_t nb_pattern,
				  const uint32_t pattern_id[],
				  uint32_t nb_action,
				  const uint32_t action_id[])
{
	uint32_t *pat = NULL;
	uint32_t *act = NULL;

	pat = nb_pattern ? malloc(sizeof(*pat) * nb_pattern) : NULL;
	act = nb_action ? malloc(sizeof(*act) * nb_action) : NULL;
	if ((nb_pattern && !pat) || (nb_action && !act))
		goto out;
	for (uint32_t i = 0; i < nb_pattern; ++i)
		pat[i] = pattern_id[i];
	for (uint32_t i = 0; i < nb_action; ++i)
		act[i] = action_id[i];
	port_flow_template_table_create(port_id, table_id, attr,
					nb_pattern, pat, nb_action, act);
out:
	free(pat);
	free(act);
}

static void
parser_flow_template_table_destroy(uint16_t port_id,
				   uint32_t nb_id,
				   const uint32_t id[])
{
	port_flow_template_table_destroy(port_id, nb_id, id);
}

static void
parser_flow_template_table_resize_complete(uint16_t port_id,
					   uint32_t table_id)
{
	port_flow_template_table_resize_complete(port_id, table_id);
}

static void
parser_flow_template_table_resize(uint16_t port_id, uint32_t table_id,
				  uint32_t nb_rules)
{
	port_flow_template_table_resize(port_id, table_id, nb_rules);
}

static void
parser_queue_flow_create(uint16_t port_id, uint16_t queue, bool postpone,
			 uint32_t table_id, uint32_t rule_id,
			 uint32_t pattern_id, uint32_t action_id,
			 const struct rte_flow_item pattern[],
			 const struct rte_flow_action actions[])
{
	port_queue_flow_create(port_id, queue, postpone, table_id, rule_id,
			       pattern_id, action_id, pattern, actions);
}

static void
parser_queue_flow_destroy(uint16_t port_id, uint16_t queue, bool postpone,
			  uint32_t rule_n, const uint64_t rule[],
			  bool is_user_id)
{
	port_queue_flow_destroy(port_id, queue, postpone, rule_n, rule);
	RTE_SET_USED(is_user_id);
}

static void
parser_queue_flow_update_resized(uint16_t port_id, uint16_t queue,
				 bool postpone, uint64_t rule_id)
{
	port_queue_flow_update_resized(port_id, queue, postpone,
				       (uint32_t)rule_id);
}

static void
parser_queue_flow_update(uint16_t port_id, uint16_t queue, bool postpone,
			 uint32_t rule_id, uint32_t action_id,
			 const struct rte_flow_action actions[])
{
	port_queue_flow_update(port_id, queue, postpone, rule_id,
			       action_id, actions);
}

static void
parser_queue_flow_push(uint16_t port_id, uint16_t queue)
{
	port_queue_flow_push(port_id, queue);
}

static void
parser_queue_flow_pull(uint16_t port_id, uint16_t queue)
{
	port_queue_flow_pull(port_id, queue);
}

static void
parser_flow_hash_calc(uint16_t port_id, uint32_t table_id,
		      uint32_t pattern_id,
		      const struct rte_flow_item pattern[])
{
	port_flow_hash_calc(port_id, table_id,
			    (uint8_t)pattern_id, pattern);
}

static void
parser_flow_hash_calc_encap(uint16_t port_id,
			    enum rte_flow_encap_hash_field field,
			    const struct rte_flow_item pattern[])
{
	port_flow_hash_calc_encap(port_id, field, pattern);
}

static void
parser_queue_flow_aged(uint16_t port_id, uint16_t queue,
		       bool destroy)
{
	port_queue_flow_aged(port_id, queue, destroy ? 1 : 0);
}

static void
parser_queue_action_handle_create(uint16_t port_id, uint16_t queue,
				  bool postpone, uint32_t group, bool is_list,
				  const struct rte_flow_indir_action_conf *conf,
				  const struct rte_flow_action actions[])
{
	port_queue_action_handle_create(port_id, queue, postpone, group,
					is_list, conf, actions);
}

static void
parser_queue_action_handle_destroy(uint16_t port_id, uint16_t queue,
				   bool postpone, uint32_t nb_id,
				   const uint32_t id[])
{
	port_queue_action_handle_destroy(port_id, queue, postpone, nb_id, id);
}

static void
parser_queue_action_handle_update(uint16_t port_id, uint16_t queue,
				  bool postpone, uint32_t group,
				  const struct rte_flow_action actions[])
{
	port_queue_action_handle_update(port_id, queue, postpone, group,
					actions);
}

static void
parser_queue_action_handle_query(uint16_t port_id, uint16_t queue,
				 bool postpone, uint32_t action_id)
{
	port_queue_action_handle_query(port_id, queue, postpone, action_id);
}

static void
parser_queue_action_handle_query_update(uint16_t port_id, uint16_t queue,
					bool postpone, uint32_t action_id,
					enum rte_flow_query_update_mode qu_mode,
					struct rte_flow_action actions[])
{
	port_queue_action_handle_query_update(port_id, queue, postpone,
					      action_id, qu_mode, actions);
}

static void
parser_action_handle_create(uint16_t port_id, uint32_t group,
			    bool is_list,
			    const struct rte_flow_indir_action_conf *conf,
			    const struct rte_flow_action actions[])
{
	port_action_handle_create(port_id, group, is_list, conf, actions);
}

static void
parser_action_handle_destroy(uint16_t port_id, uint32_t nb_id,
			     const uint32_t id[])
{
	port_action_handle_destroy(port_id, nb_id, id);
}

static void
parser_action_handle_update(uint16_t port_id, uint32_t group,
			    const struct rte_flow_action actions[])
{
	port_action_handle_update(port_id, group, actions);
}

static void
parser_action_handle_query(uint16_t port_id, uint32_t action_id)
{
	port_action_handle_query(port_id, action_id);
}

static void
parser_action_handle_query_update(uint16_t port_id, uint32_t action_id,
				  enum rte_flow_query_update_mode qu_mode,
				  struct rte_flow_action actions[])
{
	port_action_handle_query_update(port_id, action_id, qu_mode, actions);
}

static void
parser_flow_validate(uint16_t port_id, const struct rte_flow_attr *attr,
		     const struct rte_flow_item pattern[],
		     const struct rte_flow_action actions[],
		     const struct rte_flow_parser_tunnel_ops *tunnel_ops)
{
	struct tunnel_ops ops;

	port_flow_validate(port_id, attr, pattern, actions,
			   tunnel_ops ? parser_tunnel_convert(tunnel_ops, &ops)
				      : NULL);
}

static void
parser_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[],
		   const struct rte_flow_action actions[],
		   const struct rte_flow_parser_tunnel_ops *tunnel_ops,
		   uintptr_t user_id)
{
	struct tunnel_ops ops;

	port_flow_create(port_id, attr, pattern, actions,
			 tunnel_ops ? parser_tunnel_convert(tunnel_ops, &ops)
				    : NULL,
			 user_id);
}

static void
parser_flow_destroy(uint16_t port_id, uint32_t nb_rule, const uint64_t rule[],
		    bool is_user_id)
{
	port_flow_destroy(port_id, nb_rule, rule, is_user_id);
}

static void
parser_flow_update(uint16_t port_id, uint32_t rule_id,
		   const struct rte_flow_action actions[],
		   uintptr_t user_id)
{
	port_flow_update(port_id, rule_id, actions, user_id != 0);
}

static void
parser_flow_flush(uint16_t port_id)
{
	port_flow_flush(port_id);
}

static void
parser_flow_dump(uint16_t port_id, bool all, uint64_t rule, const char *file,
		 bool is_user_id)
{
	port_flow_dump(port_id, all, rule, file, is_user_id);
}

static void
parser_flow_query(uint16_t port_id, uint64_t rule,
		  struct rte_flow_action *action, bool is_user_id)
{
	port_flow_query(port_id, rule, action, is_user_id);
}

static void
parser_flow_list(uint16_t port_id, uint32_t group_n, const uint32_t group[])
{
	port_flow_list(port_id, group_n, group);
}

static void
parser_flow_isolate(uint16_t port_id, int set)
{
	port_flow_isolate(port_id, set);
}

static void
parser_flow_aged(uint16_t port_id, int destroy)
{
	port_flow_aged(port_id, destroy);
}

static void
parser_flow_tunnel_create(uint16_t port_id,
			  const struct rte_flow_parser_tunnel_ops *ops_cfg)
{
	struct tunnel_ops ops;

	port_flow_tunnel_create(port_id,
				ops_cfg ? parser_tunnel_convert(ops_cfg, &ops)
					: NULL);
}

static void
parser_flow_tunnel_destroy(uint16_t port_id, uint32_t id)
{
	port_flow_tunnel_destroy(port_id, id);
}

static void
parser_flow_tunnel_list(uint16_t port_id)
{
	port_flow_tunnel_list(port_id);
}

static void
parser_meter_policy_add(uint16_t port_id, uint32_t policy_id,
			const struct rte_flow_action actions[])
{
	port_meter_policy_add(port_id, policy_id, actions);
}

static void
parser_flex_item_create(uint16_t port_id, uint16_t token,
			const char *filename)
{
	flex_item_create(port_id, token, filename);
}

static void
parser_flex_item_destroy(uint16_t port_id, uint16_t token)
{
	flex_item_destroy(port_id, token);
}

static const struct rte_flow_parser_ops_query parser_query_ops = {
	.port_validate = parser_port_validate,
	.flow_rule_count = parser_flow_rule_count,
	.flow_rule_id_get = parser_flow_rule_id_get,
	.pattern_template_count = parser_pattern_template_count,
	.pattern_template_id_get = parser_pattern_template_id_get,
	.actions_template_count = parser_actions_template_count,
	.actions_template_id_get = parser_actions_template_id_get,
	.table_count = parser_table_count,
	.table_id_get = parser_table_id_get,
	.queue_count = parser_queue_count,
	.rss_queue_count = parser_rss_queue_count,
	.table_get = parser_table_get,
	.action_handle_get = parser_action_handle_get,
	.meter_profile_get = parser_meter_profile_get,
	.meter_policy_get = parser_meter_policy_get,
	.verbose_level_get = parser_verbose_level_get,
	.flex_handle_get = parser_flex_handle_get,
	.flex_pattern_get = parser_flex_pattern_get,
};

static const struct rte_flow_parser_ops_command parser_command_ops = {
	.flow_get_info = parser_flow_get_info,
	.flow_configure = parser_flow_configure,
	.flow_pattern_template_create = parser_flow_pattern_template_create,
	.flow_pattern_template_destroy = parser_flow_pattern_template_destroy,
	.flow_actions_template_create = parser_flow_actions_template_create,
	.flow_actions_template_destroy = parser_flow_actions_template_destroy,
	.flow_template_table_create = parser_flow_template_table_create,
	.flow_template_table_destroy = parser_flow_template_table_destroy,
	.flow_template_table_resize_complete =
		parser_flow_template_table_resize_complete,
	.queue_group_set_miss_actions = parser_queue_group_set_miss_actions,
	.flow_template_table_resize = parser_flow_template_table_resize,
	.queue_flow_create = parser_queue_flow_create,
	.queue_flow_destroy = parser_queue_flow_destroy,
	.queue_flow_update_resized = parser_queue_flow_update_resized,
	.queue_flow_update = parser_queue_flow_update,
	.queue_flow_push = parser_queue_flow_push,
	.queue_flow_pull = parser_queue_flow_pull,
	.flow_hash_calc = parser_flow_hash_calc,
	.flow_hash_calc_encap = parser_flow_hash_calc_encap,
	.queue_flow_aged = parser_queue_flow_aged,
	.queue_action_handle_create = parser_queue_action_handle_create,
	.queue_action_handle_destroy = parser_queue_action_handle_destroy,
	.queue_action_handle_update = parser_queue_action_handle_update,
	.queue_action_handle_query = parser_queue_action_handle_query,
	.queue_action_handle_query_update =
		parser_queue_action_handle_query_update,
	.action_handle_create = parser_action_handle_create,
	.action_handle_destroy = parser_action_handle_destroy,
	.action_handle_update = parser_action_handle_update,
	.action_handle_query = parser_action_handle_query,
	.action_handle_query_update = parser_action_handle_query_update,
	.flow_validate = parser_flow_validate,
	.flow_create = parser_flow_create,
	.flow_destroy = parser_flow_destroy,
	.flow_update = parser_flow_update,
	.flow_flush = parser_flow_flush,
	.flow_dump = parser_flow_dump,
	.flow_query = parser_flow_query,
	.flow_list = parser_flow_list,
	.flow_isolate = parser_flow_isolate,
	.flow_aged = parser_flow_aged,
	.flow_tunnel_create = parser_flow_tunnel_create,
	.flow_tunnel_destroy = parser_flow_tunnel_destroy,
	.flow_tunnel_list = parser_flow_tunnel_list,
	.meter_policy_add = parser_meter_policy_add,
	.flex_item_create = parser_flex_item_create,
	.flex_item_destroy = parser_flex_item_destroy,
};

static const struct rte_flow_parser_ops parser_ops = {
	.query = &parser_query_ops,
	.command = &parser_command_ops,
};

int
testpmd_flow_parser_init(void)
{
	return rte_flow_parser_init(&parser_ops);
}

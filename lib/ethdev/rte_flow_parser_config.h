/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

/**
 * @file
 * Flow Parser Library - Configuration Types and Full Command Parsing
 *
 * This header provides the configuration data types, output structures,
 * and the full command parser (rte_flow_parser_parse()). Applications
 * that need cmdline token integration (tab completion, dynamic tokens)
 * should additionally include rte_flow_parser_cmdline.h from lib/cmdline.
 *
 * For simple string-to-flow parsing only, rte_flow_parser.h suffices.
 *
 * @warning None of the functions in this header are thread-safe. The parser
 * uses a single global context shared across all threads; no function in
 * this header or in rte_flow_parser.h may be called concurrently, even
 * with different port IDs. All calls must be serialized by the application
 * (e.g., by confining all parser usage to a single thread).
 */

#ifndef RTE_FLOW_PARSER_CONFIG_H
#define RTE_FLOW_PARSER_CONFIG_H

#include <stdbool.h>

#include <rte_ether.h>
#include <rte_flow_parser.h>
#include <rte_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size in bytes of a raw encap/decap header blob. */
#define ACTION_RAW_ENCAP_MAX_DATA 512
/** Maximum number of raw encap/decap configuration slots. */
#define RAW_ENCAP_CONFS_MAX_NUM 8
/** Maximum number of RSS queues in a single action. */
#define ACTION_RSS_QUEUE_NUM 128
/** Number of flow items in a VXLAN encap action definition. */
#define ACTION_VXLAN_ENCAP_ITEMS_NUM 6
/** Number of flow items in an NVGRE encap action definition. */
#define ACTION_NVGRE_ENCAP_ITEMS_NUM 5
/** Maximum size in bytes of an IPv6 extension push header blob. */
#define ACTION_IPV6_EXT_PUSH_MAX_DATA 512
/** Maximum number of IPv6 extension push configuration slots. */
#define IPV6_EXT_PUSH_CONFS_MAX_NUM 8
/** Maximum number of sub-actions in a sample action. */
#define ACTION_SAMPLE_ACTIONS_NUM 10
/** Maximum number of sample action configuration slots. */
#define RAW_SAMPLE_CONFS_MAX_NUM 8
/** Length of an RSS hash key in bytes. */
#ifndef RSS_HASH_KEY_LENGTH
#define RSS_HASH_KEY_LENGTH 64
#endif

/**
 * @name Encap/decap configuration structures
 *
 * These structures hold tunnel encapsulation parameters that the parser
 * reads when constructing VXLAN_ENCAP, NVGRE_ENCAP, L2_ENCAP/DECAP,
 * and MPLSoGRE/MPLSoUDP encap/decap actions. Applications configure
 * them via the accessor functions below before parsing flow rules that
 * reference these actions.
 * @{
 */

/** VXLAN encapsulation parameters. */
struct rte_flow_parser_vxlan_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint32_t select_tos_ttl:1; /**< Set TOS/TTL fields. */
	uint8_t vni[3];          /**< VXLAN Network Identifier (big-endian). */
	rte_be16_t udp_src;      /**< Outer UDP source port. */
	rte_be16_t udp_dst;      /**< Outer UDP destination port. */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	uint8_t ip_tos;          /**< IP Type of Service / Traffic Class. */
	uint8_t ip_ttl;          /**< IP Time to Live / Hop Limit. */
	struct rte_ether_addr eth_src; /**< Outer Ethernet source address. */
	struct rte_ether_addr eth_dst; /**< Outer Ethernet destination address. */
};

/** NVGRE encapsulation parameters. */
struct rte_flow_parser_nvgre_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint8_t tni[3];          /**< Tenant Network Identifier (big-endian). */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer Ethernet source address. */
	struct rte_ether_addr eth_dst; /**< Outer Ethernet destination address. */
};

/** L2 encapsulation parameters. */
struct rte_flow_parser_l2_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer Ethernet source address. */
	struct rte_ether_addr eth_dst; /**< Outer Ethernet destination address. */
};

/** L2 decapsulation parameters. */
struct rte_flow_parser_l2_decap_conf {
	uint32_t select_vlan:1;  /**< Expect VLAN header in decap. */
};

/** MPLSoGRE encapsulation parameters. */
struct rte_flow_parser_mplsogre_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint8_t label[3];        /**< MPLS label (big-endian). */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer source MAC. */
	struct rte_ether_addr eth_dst; /**< Outer destination MAC. */
};

/** MPLSoGRE decapsulation parameters. */
struct rte_flow_parser_mplsogre_decap_conf {
	uint32_t select_ipv4:1;  /**< Expect IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Expect VLAN header. */
};

/** MPLSoUDP encapsulation parameters. */
struct rte_flow_parser_mplsoudp_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint8_t label[3];        /**< MPLS label (big-endian). */
	rte_be16_t udp_src;      /**< Outer UDP source port. */
	rte_be16_t udp_dst;      /**< Outer UDP destination port. */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer source MAC. */
	struct rte_ether_addr eth_dst; /**< Outer destination MAC. */
};

/** MPLSoUDP decapsulation parameters. */
struct rte_flow_parser_mplsoudp_decap_conf {
	uint32_t select_ipv4:1;  /**< Expect IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Expect VLAN header. */
};

/** Raw encap configuration slot. */
struct rte_flow_parser_raw_encap_data {
	uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
	uint8_t preserve[ACTION_RAW_ENCAP_MAX_DATA];
	size_t size;
};

/** Raw decap configuration slot. */
struct rte_flow_parser_raw_decap_data {
	uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
	size_t size;
};

/** IPv6 extension push configuration slot. */
struct rte_flow_parser_ipv6_ext_push_data {
	uint8_t data[ACTION_IPV6_EXT_PUSH_MAX_DATA];
	size_t size;
	uint8_t type;
};

/** IPv6 extension remove configuration slot. */
struct rte_flow_parser_ipv6_ext_remove_data {
	uint8_t type;
};

/** VXLAN encap action data (used in sample slots). */
struct rte_flow_parser_action_vxlan_encap_data {
	struct rte_flow_action_vxlan_encap conf;
	struct rte_flow_item items[ACTION_VXLAN_ENCAP_ITEMS_NUM];
	struct rte_flow_item_eth item_eth;
	struct rte_flow_item_vlan item_vlan;
	union {
		struct rte_flow_item_ipv4 item_ipv4;
		struct rte_flow_item_ipv6 item_ipv6;
	};
	struct rte_flow_item_udp item_udp;
	struct rte_flow_item_vxlan item_vxlan;
};

/** NVGRE encap action data (used in sample slots). */
struct rte_flow_parser_action_nvgre_encap_data {
	struct rte_flow_action_nvgre_encap conf;
	struct rte_flow_item items[ACTION_NVGRE_ENCAP_ITEMS_NUM];
	struct rte_flow_item_eth item_eth;
	struct rte_flow_item_vlan item_vlan;
	union {
		struct rte_flow_item_ipv4 item_ipv4;
		struct rte_flow_item_ipv6 item_ipv6;
	};
	struct rte_flow_item_nvgre item_nvgre;
};

/** RSS action data (used in sample slots). */
struct rte_flow_parser_action_rss_data {
	struct rte_flow_action_rss conf;
	uint8_t key[RSS_HASH_KEY_LENGTH];
	uint16_t queue[ACTION_RSS_QUEUE_NUM];
};

/** Sample actions configuration slot. */
struct rte_flow_parser_sample_slot {
	struct rte_flow_action data[ACTION_SAMPLE_ACTIONS_NUM];
	struct rte_flow_parser_action_vxlan_encap_data vxlan_encap;
	struct rte_flow_parser_action_nvgre_encap_data nvgre_encap;
	struct rte_flow_parser_action_rss_data rss_data;
	struct rte_flow_action_raw_encap raw_encap;
};

/** @} */

/**
 * Tunnel steering/match flags used by the parser.
 */
struct rte_flow_parser_tunnel_ops {
	uint32_t id;         /**< Tunnel object identifier. */
	char type[16];       /**< Tunnel type name (e.g., "vxlan"). */
	uint32_t enabled:1;  /**< Tunnel steering enabled. */
	uint32_t actions:1;  /**< Apply tunnel to actions. */
	uint32_t items:1;    /**< Apply tunnel to pattern items. */
};

/**
 * Flow parser command identifiers.
 *
 * These identify the command type in the rte_flow_parser_output structure
 * after a successful parse. Internal grammar tokens used during parsing
 * are not exposed.
 *
 * When adding a new command, update the conversion in parser_token_to_command().
 */
enum rte_flow_parser_command {
	RTE_FLOW_PARSER_CMD_UNKNOWN = 0,

	/* Flow operations */
	RTE_FLOW_PARSER_CMD_INFO,
	RTE_FLOW_PARSER_CMD_CONFIGURE,
	RTE_FLOW_PARSER_CMD_VALIDATE,
	RTE_FLOW_PARSER_CMD_CREATE,
	RTE_FLOW_PARSER_CMD_DESTROY,
	RTE_FLOW_PARSER_CMD_UPDATE,
	RTE_FLOW_PARSER_CMD_FLUSH,
	RTE_FLOW_PARSER_CMD_DUMP_ALL,
	RTE_FLOW_PARSER_CMD_DUMP_ONE,
	RTE_FLOW_PARSER_CMD_QUERY,
	RTE_FLOW_PARSER_CMD_LIST,
	RTE_FLOW_PARSER_CMD_AGED,
	RTE_FLOW_PARSER_CMD_ISOLATE,
	RTE_FLOW_PARSER_CMD_PUSH,
	RTE_FLOW_PARSER_CMD_PULL,
	RTE_FLOW_PARSER_CMD_HASH,

	/* Template operations */
	RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_CREATE,
	RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_DESTROY,
	RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_CREATE,
	RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_DESTROY,

	/* Table operations */
	RTE_FLOW_PARSER_CMD_TABLE_CREATE,
	RTE_FLOW_PARSER_CMD_TABLE_DESTROY,
	RTE_FLOW_PARSER_CMD_TABLE_RESIZE,
	RTE_FLOW_PARSER_CMD_TABLE_RESIZE_COMPLETE,

	/* Group operations */
	RTE_FLOW_PARSER_CMD_GROUP_SET_MISS_ACTIONS,

	/* Queue operations */
	RTE_FLOW_PARSER_CMD_QUEUE_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_DESTROY,
	RTE_FLOW_PARSER_CMD_QUEUE_UPDATE,
	RTE_FLOW_PARSER_CMD_QUEUE_FLOW_UPDATE_RESIZED,
	RTE_FLOW_PARSER_CMD_QUEUE_AGED,

	/* Indirect action operations */
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_CREATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_UPDATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_DESTROY,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY_UPDATE,

	/* Queue indirect action operations */
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_UPDATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_DESTROY,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY_UPDATE,

	/* Tunnel operations */
	RTE_FLOW_PARSER_CMD_TUNNEL_CREATE,
	RTE_FLOW_PARSER_CMD_TUNNEL_DESTROY,
	RTE_FLOW_PARSER_CMD_TUNNEL_LIST,

	/* Flex item operations */
	RTE_FLOW_PARSER_CMD_FLEX_ITEM_CREATE,
	RTE_FLOW_PARSER_CMD_FLEX_ITEM_DESTROY,

	/* Meter policy */
	RTE_FLOW_PARSER_CMD_ACTION_POL_G,

	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_FLOW_CONF_CREATE,
};

/** Parser output buffer layout expected by rte_flow_parser_parse(). */
struct rte_flow_parser_output {
	enum rte_flow_parser_command command; /**< Flow command. */
	uint16_t port; /**< Affected port ID. */
	uint16_t queue; /**< Async queue ID. */
	bool postpone; /**< Postpone async operation. */
	union {
		struct {
			struct rte_flow_port_attr port_attr;
			uint32_t nb_queue;
			struct rte_flow_queue_attr queue_attr;
		} configure; /**< Configuration arguments. */
		struct {
			uint32_t *template_id;
			uint32_t template_id_n;
		} templ_destroy; /**< Template destroy arguments. */
		struct {
			uint32_t id;
			struct rte_flow_template_table_attr attr;
			uint32_t *pat_templ_id;
			uint32_t pat_templ_id_n;
			uint32_t *act_templ_id;
			uint32_t act_templ_id_n;
		} table; /**< Table arguments. */
		struct {
			uint32_t *table_id;
			uint32_t table_id_n;
		} table_destroy; /**< Table destroy arguments. */
		struct {
			uint32_t *action_id;
			uint32_t action_id_n;
		} ia_destroy; /**< Indirect action destroy arguments. */
		struct {
			uint32_t action_id;
			enum rte_flow_query_update_mode qu_mode;
		} ia; /**< Indirect action query arguments. */
		struct {
			uint32_t table_id;
			uint32_t pat_templ_id;
			uint32_t rule_id;
			uint32_t act_templ_id;
			struct rte_flow_attr attr;
			struct rte_flow_parser_tunnel_ops tunnel_ops;
			uintptr_t user_id;
			struct rte_flow_item *pattern;
			struct rte_flow_action *actions;
			struct rte_flow_action *masks;
			uint32_t pattern_n;
			uint32_t actions_n;
			uint8_t *data;
			enum rte_flow_encap_hash_field field;
			uint8_t encap_hash;
			bool is_user_id;
		} vc; /**< Validate/create arguments. */
		struct {
			uint64_t *rule;
			uint64_t rule_n;
			bool is_user_id;
		} destroy; /**< Destroy arguments. */
		struct {
			char file[128];
			bool mode;
			uint64_t rule;
			bool is_user_id;
		} dump; /**< Dump arguments. */
		struct {
			uint64_t rule;
			struct rte_flow_action action;
			bool is_user_id;
		} query; /**< Query arguments. */
		struct {
			uint32_t *group;
			uint32_t group_n;
		} list; /**< List arguments. */
		struct {
			int set;
		} isolate; /**< Isolated mode arguments. */
		struct {
			int destroy;
		} aged; /**< Aged arguments. */
		struct {
			uint32_t policy_id;
		} policy; /**< Policy arguments. */
		struct {
			uint16_t token;
			uintptr_t uintptr;
			char filename[128];
		} flex; /**< Flex arguments. */
	} args; /**< Command arguments. */
};

/**
 * Kind of items to parse in a SET context.
 */
enum rte_flow_parser_set_item_kind {
	RTE_FLOW_PARSER_SET_ITEMS_PATTERN,   /**< Pattern items (next_item). */
	RTE_FLOW_PARSER_SET_ITEMS_ACTION,    /**< Action items (sample). */
	RTE_FLOW_PARSER_SET_ITEMS_IPV6_EXT,  /**< IPv6 ext push/remove items. */
};

/**
 * Dispatch callback type for parsed flow commands.
 *
 * Called by rte_flow_parser_cmd_flow_cb() after the cmdline library
 * finishes parsing a complete flow command. The application implements
 * this to act on the parsed result (e.g., call port_flow_create()).
 *
 * @param in
 *   Parsed output buffer containing the command and its arguments.
 */
typedef void (*rte_flow_parser_dispatch_t)(const struct rte_flow_parser_output *in);

/**
 * Configuration registration for the flow parser.
 *
 * Applications must register configuration storage before using the
 * full command parser (rte_flow_parser_parse) or encap-dependent actions.
 * The simple API (rte_flow_parser_parse_pattern_str, etc.) works
 * without registration.
 *
 * For cmdline integration (dynamic tokens, tab completion), additionally
 * call rte_flow_parser_cmdline_register() from rte_flow_parser_cmdline.h.
 */
struct rte_flow_parser_config {
	/* Single-instance configs */
	struct rte_flow_parser_vxlan_encap_conf *vxlan_encap;
	struct rte_flow_parser_nvgre_encap_conf *nvgre_encap;
	struct rte_flow_parser_l2_encap_conf *l2_encap;
	struct rte_flow_parser_l2_decap_conf *l2_decap;
	struct rte_flow_parser_mplsogre_encap_conf *mplsogre_encap;
	struct rte_flow_parser_mplsogre_decap_conf *mplsogre_decap;
	struct rte_flow_parser_mplsoudp_encap_conf *mplsoudp_encap;
	struct rte_flow_parser_mplsoudp_decap_conf *mplsoudp_decap;
	struct rte_flow_action_conntrack *conntrack;
	/* Multi-instance configs (app-provided pointer arrays) */
	struct {
		struct rte_flow_parser_raw_encap_data *slots;
		uint16_t count;
	} raw_encap;
	struct {
		struct rte_flow_parser_raw_decap_data *slots;
		uint16_t count;
	} raw_decap;
	struct {
		struct rte_flow_parser_ipv6_ext_push_data *slots;
		uint16_t count;
	} ipv6_ext_push;
	struct {
		struct rte_flow_parser_ipv6_ext_remove_data *slots;
		uint16_t count;
	} ipv6_ext_remove;
	struct {
		struct rte_flow_parser_sample_slot *slots;
		uint16_t count;
	} sample;
};

/**
 * Register application-owned configuration storage.
 *
 * Must be called before using the full command parser or encap actions.
 * The simple parsing API works without registration.
 *
 * The config struct is copied by value, but all pointers within it
 * remain owned by the application and must stay valid for the parser's
 * lifetime.
 *
 * Calling this function again replaces the previous registration and
 * frees any indirect action list configurations created by prior
 * parsing sessions.
 *
 * @param config
 *   Configuration with pointers to app-owned storage.
 * @return
 *   0 on success, negative errno on failure.
 */
__rte_experimental
int rte_flow_parser_config_register(const struct rte_flow_parser_config *config);

/**
 * Parse a flow CLI string.
 *
 * Parses a complete flow command string and fills the output buffer.
 *
 * @param src
 *   NUL-terminated string containing one or more flow commands.
 * @param result
 *   Output buffer where the parsed result is stored.
 * @param result_size
 *   Size of the output buffer in bytes.
 * @return
 *   0 on success, -EINVAL on syntax error, -ENOBUFS if result_size is too
 *   small, or a negative errno-style value on other errors.
 */
__rte_experimental
int rte_flow_parser_parse(const char *src,
			  struct rte_flow_parser_output *result,
			  size_t result_size);

/**
 * Initialize parse context for item tokenization in SET commands.
 *
 * Sets up the internal parser context so that subsequent
 * rte_flow_parser_set_item_tok() calls parse pattern or action items.
 *
 * @param kind
 *   Which item list to push (pattern, action, or ipv6_ext).
 * @param object
 *   Object pointer used by item parse callbacks. May be NULL.
 * @param size
 *   Size of the object area (reserved for future use).
 */
__rte_experimental
void rte_flow_parser_set_ctx_init(enum rte_flow_parser_set_item_kind kind,
				  void *object, unsigned int size);

/**
 * @name Multi-instance configuration accessors
 * @{
 */

__rte_experimental
const struct rte_flow_action_raw_encap *rte_flow_parser_raw_encap_conf(uint16_t index);

__rte_experimental
const struct rte_flow_action_raw_decap *rte_flow_parser_raw_decap_conf(uint16_t index);

__rte_experimental
int rte_flow_parser_raw_encap_conf_set(uint16_t index,
				       const struct rte_flow_item pattern[],
				       uint32_t pattern_n);

__rte_experimental
int rte_flow_parser_raw_decap_conf_set(uint16_t index,
				       const struct rte_flow_item pattern[],
				       uint32_t pattern_n);

__rte_experimental
int rte_flow_parser_ipv6_ext_push_set(uint16_t index,
				      const struct rte_flow_item *pattern,
				      uint32_t pattern_n);

__rte_experimental
int rte_flow_parser_ipv6_ext_remove_set(uint16_t index,
					const struct rte_flow_item *pattern,
					uint32_t pattern_n);

__rte_experimental
int rte_flow_parser_sample_actions_set(uint16_t index,
				       const struct rte_flow_action *actions,
				       uint32_t actions_n);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PARSER_CONFIG_H */

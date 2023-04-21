/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef _TESTGRAPH_H_
#define _TESTGRAPH_H_

#include <stdbool.h>

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_node_eth_api.h>

#include <cmdline.h>
#include <cmdline_parse.h>


#define MAX_LCORE_PARAMS 1024
#define MAX_NODE_PATTERNS 128

#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif

#define TEST_GRAPH_ETHDEV_RX_NODE BIT_ULL(0)
#define TEST_GRAPH_ETHDEV_TX_NODE BIT_ULL(1)
#define TEST_GRAPH_PUNT_KERNEL_NODE BIT_ULL(2)
#define TEST_GRAPH_KERNEL_RECV_NODE BIT_ULL(3)
#define TEST_GRAPH_IP4_LOOKUP_NODE BIT_ULL(4)
#define TEST_GRAPH_IP4_REWRITE_NODE BIT_ULL(5)
#define TEST_GRAPH_PKT_CLS_NODE BIT_ULL(6)
#define TEST_GRAPH_PKT_DROP_NODE BIT_ULL(7)
#define TEST_GRAPH_NULL_NODE BIT_ULL(8)

extern uint8_t cl_quit;
static volatile bool force_quit;

extern struct rte_node_ethdev_config ethdev_conf[RTE_MAX_ETHPORTS];
extern uint32_t enabled_port_mask;
extern uint32_t nb_conf;

extern int promiscuous_on;	   /**< Ports set in promiscuous mode off by default. */
extern uint8_t interactive;	   /**< interactive mode is disabled by default. */
extern uint32_t enabled_port_mask; /**< Mask of enabled ports */
extern int numa_on;		   /**< NUMA is enabled by default. */
extern int per_port_pool;

extern volatile bool graph_walk_quit;
extern volatile bool run_graph_walk;
extern struct rte_graph_cluster_stats *stats;

extern char node_pattern[MAX_NODE_PATTERNS][RTE_NODE_NAMESIZE];
extern uint8_t num_patterns;

struct node_list {
	const char *nodes[MAX_NODE_PATTERNS];
	uint64_t test_id;
	uint8_t size;
};

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

void prompt(void);
void prompt_exit(void);
int init_cmdline(void);
int validate_config(void);
int parse_cmdline_args(int argc, char **argv);
uint32_t ethdev_ports_setup(void);
void ethdev_rxq_configure(void);
void ethdev_txq_configure(void);
void start_eth_ports(void);
void stop_eth_ports(void);
int create_graph(char pattern[][RTE_NODE_NAMESIZE], uint8_t num_patterns);
int destroy_graph(void);
int graph_main_loop(void *conf);
struct rte_graph_cluster_stats *create_graph_cluster_stats(void);
void check_all_ports_link_status(uint32_t port_mask);
int configure_graph_nodes(uint64_t valid_nodes);

int parse_config(const char *q_arg);
int parse_node_patterns(const char *q_arg);
int validate_node_names(uint64_t *valid_nodes);
void cleanup_node_pattern(void);

#define TESTGRAPH_LOG(level, fmt, args...)                                                         \
	rte_log(RTE_LOG_##level, testgraph_logtype, "testgraph: " fmt, ##args)

#endif /* _TESTGRAPH_H_ */

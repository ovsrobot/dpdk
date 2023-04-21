/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <fnmatch.h>
#include <signal.h>
#include <stdlib.h>

#include <rte_bus.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <ethdev_rx_priv.h>
#include <ethdev_tx_priv.h>
#include <punt_kernel_priv.h>

#include "testgraph.h"

/* Log type */
#define RTE_LOGTYPE_TEST_GRAPH RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_RX_QUEUE_PER_LCORE 16

#define NB_SOCKETS 8

/* Static global variables used within this file. */
uint16_t nb_rxd = RX_DESC_DEFAULT;
uint16_t nb_txd = TX_DESC_DEFAULT;

static volatile bool force_quit;
volatile bool graph_walk_quit;

volatile bool run_graph_walk = true;

uint8_t cl_quit;

uint8_t interactive; /**< interactive mode is off by default */

const char **node_patterns;

char node_pattern[MAX_NODE_PATTERNS][RTE_NODE_NAMESIZE] = {0};
uint8_t num_patterns;

int promiscuous_on; /**< Ports set in promiscuous mode off by default. */

int numa_on = 1;   /**< NUMA is enabled by default. */
int per_port_pool; /**< Use separate buffer pools per port; disabled */
		   /**< by default */

int testgraph_logtype; /**< Log type for testpmd logs */

struct rte_graph_cluster_stats *stats;

/* Mask of enabled ports */
uint32_t enabled_port_mask;

uint32_t nb_conf;

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
	char node_name[RTE_NODE_NAMESIZE];
};

struct lcore_tx_queue {
	char node_name[RTE_NODE_NAMESIZE];
};

/* Lcore conf */
struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	char punt_kernel_node_name[RTE_NODE_NAMESIZE];

	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 2}, {1, 0, 2}, {2, 0, 2}, {0, 1, 3}, {1, 1, 3},
	{2, 1, 3}, {0, 2, 4}, {1, 2, 4}, {2, 2, 4},
};

struct lcore_params *lcore_params = lcore_params_array_default;
uint16_t nb_lcore_params = RTE_DIM(lcore_params_array_default);

static struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_RSS,
		},
	.rx_adv_conf = {
			.rss_conf = {
					.rss_key = NULL,
					.rss_hf = RTE_ETH_RSS_IP,
				},
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
};

static const struct node_list test_node_list[] = {{{"ethdev_rx", "ethdev_tx"}, 0, 2},
						{{"ethdev_rx", "punt_kernel"}, 0, 2} };

static const struct node_list supported_nodes[] = {{{"ethdev_rx"}, TEST_GRAPH_ETHDEV_RX_NODE, 1},
						{{"ethdev_tx"}, TEST_GRAPH_ETHDEV_TX_NODE, 1},
						{{"punt_kernel"}, TEST_GRAPH_PUNT_KERNEL_NODE, 1},
						{{"kernel_recv"}, TEST_GRAPH_KERNEL_RECV_NODE, 1},
						{{"ip4_lookup"}, TEST_GRAPH_IP4_LOOKUP_NODE, 1},
						{{"ip4_rewrite"}, TEST_GRAPH_IP4_REWRITE_NODE, 1},
						{{"pkt_cls"}, TEST_GRAPH_PKT_CLS_NODE, 1},
						{{"pkt_drop"}, TEST_GRAPH_PKT_DROP_NODE, 1},
						{{"NULL"}, TEST_GRAPH_NULL_NODE, 1} };

static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][NB_SOCKETS];

struct rte_node_ethdev_config ethdev_conf[RTE_MAX_ETHPORTS];

static int
check_lcore_params(void)
{
	uint8_t queue, lcore;
	int socketid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			printf("Invalid queue number: %hhu\n", queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			printf("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
			return -1;
		}

		if (lcore == rte_get_main_lcore()) {
			printf("Error: lcore %u is main lcore\n", lcore);
			return -1;
		}
		socketid = rte_lcore_to_socket_id(lcore);
		if ((socketid != 0) && (numa_on == 0)) {
			printf("Warning: lcore %hhu is on socket %d with numa off\n", lcore,
			       socketid);
		}
	}

	return 0;
}

static int
check_port_config(void)
{
	uint16_t portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("Port %u is not enabled in port mask\n", portid);
			return -1;
		}
		if (!rte_eth_dev_is_valid_port(portid)) {
			printf("Port %u is not present on the board\n", portid);
			return -1;
		}
	}

	return 0;
}

static uint8_t
get_port_n_rx_queues(const uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue + 1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE,
					 "Queue ids of the port %d must be"
					 " in sequence and must start with 0\n",
					 lcore_params[i].port_id);
		}
	}

	return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			printf("Error: too many queues (%u) for lcore: %u\n",
			       (unsigned int)nb_rx_queue + 1, (unsigned int)lcore);
			return -1;
		}

		lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id = lcore_params[i].port_id;
		lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id = lcore_params[i].queue_id;
		lcore_conf[lcore].n_rx_queue++;
	}

	return 0;
}

int
validate_config(void)
{
	int rc = -1;

	if (check_lcore_params() < 0) {
		printf("check_lcore_params() failed\n");
		goto exit;
	}

	if (init_lcore_rx_queues() < 0) {
		printf("init_lcore_rx_queues() failed\n");
		goto exit;
	}

	if (check_port_config() < 0) {
		printf("check_port_config() failed\n");
		goto exit;
	}

	return 0;

exit:
	return rc;
}

#define MEMPOOL_CACHE_SIZE 256

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports)                                                                            \
	RTE_MAX((nports * nb_rx_queue * nb_rxd + nports * nb_lcores * RTE_GRAPH_BURST_SIZE +       \
		 nports * nb_tx_queue * nb_txd + nb_lcores * MEMPOOL_CACHE_SIZE),                  \
		8192u)

static int
init_mem(uint16_t portid, uint32_t nb_mbuf)
{
	uint32_t lcore_id;
	int socketid;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
				 socketid, lcore_id, NB_SOCKETS);
		}

		if (pktmbuf_pool[portid][socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d:%d", portid, socketid);
			/* Create a pool with priv size of a cacheline */
			pktmbuf_pool[portid][socketid] = rte_pktmbuf_pool_create(
				s, nb_mbuf, MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE,
				RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[portid][socketid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n",
					 socketid);
			else
				printf("Allocated mbuf pool on socket %d\n", socketid);
		}
	}

	return 0;
}

void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t portid;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n", portid,
					       rte_strerror(-ret));
				continue;
			}
			/* Print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
						    &link);
				printf("Port %d %s\n", portid, link_status_text);
				continue;
			}
			/* Clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* After finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* Set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("Done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
	prompt_exit();
}

int
graph_main_loop(void *conf)
{
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	graph = qconf->graph;

	if (!graph) {
		RTE_LOG(INFO, TEST_GRAPH, "Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, TEST_GRAPH, "Entering main loop on lcore %u, graph %s(%p)\n", lcore_id,
		qconf->name, graph);

	while (likely(!force_quit & !graph_walk_quit)) {
		if (likely(run_graph_walk))
			rte_graph_walk(graph);
	}

	return 0;
}

struct rte_graph_cluster_stats *
create_graph_cluster_stats(void)
{
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stat;
	const char *pattern = "worker_*";

	/* Prepare stats object */
	memset(&s_param, 0, sizeof(s_param));
	s_param.f = stdout;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = &pattern;
	s_param.nb_graph_patterns = 1;

	stat = rte_graph_cluster_stats_create(&s_param);
	if (stat == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create stats object\n");

	return stat;
}

static void
print_stats(void)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};

	while (!force_quit) {
		/* Clear screen and move to top left */
		printf("%s%s", clr, topLeft);
		rte_graph_cluster_stats_get(stats, 0);
		rte_delay_ms(1E3);
	}

	rte_graph_cluster_stats_destroy(stats);
}

int
parse_config(const char *q_arg)
{
	enum fieldnames { FLD_PORT = 0, FLD_QUEUE, FLD_LCORE, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	nb_lcore_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			goto exit;

		size = p0 - p;
		if (size >= sizeof(s))
			goto exit;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			goto exit;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				goto exit;
		}

		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			printf("Exceeded max number of lcore params: %hu\n", nb_lcore_params);
			goto exit;
		}

		if (int_fld[FLD_PORT] >= RTE_MAX_ETHPORTS || int_fld[FLD_LCORE] >= RTE_MAX_LCORE) {
			printf("Invalid port/lcore id\n");
			goto exit;
		}

		lcore_params_array[nb_lcore_params].port_id = (uint8_t)int_fld[FLD_PORT];
		lcore_params_array[nb_lcore_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	lcore_params = lcore_params_array;

	return 0;
exit:
	/* Revert to default config */
	lcore_params = lcore_params_array_default;
	nb_lcore_params = RTE_DIM(lcore_params_array_default);

	return -1;
}

int
parse_node_patterns(const char *q_arg)
{
	const char *p, *p0 = q_arg;
	int ret = -EINVAL;
	uint32_t size;

	num_patterns = 0;

	p = strchr(p0, '(');
	if (p != NULL) {
		++p;
		while ((p0 = strchr(p, ',')) != NULL) {
			size = p0 - p;
			if (size >= RTE_NODE_NAMESIZE)
				goto exit;

			if (num_patterns >= MAX_NODE_PATTERNS) {
				printf("Too many nodes passed.\n");
				goto exit;
			}

			memcpy(node_pattern[num_patterns++], p, size);
			p = p0 + 1;
		}

		p0 = strchr(p, ')');
		if (p0 != NULL) {
			size = p0 - p;
			if (size >= RTE_NODE_NAMESIZE)
				goto exit;

			if (num_patterns >= MAX_NODE_PATTERNS) {
				printf("Too many nodes passed.\n");
				goto exit;
			}

			memcpy(node_pattern[num_patterns++], p, size);
		} else {
			goto exit;
		}
	} else {
		goto exit;
	}

	return 0;
exit:
	return ret;
}

static void
set_default_node_pattern(void)
{
	uint16_t idx;

	for (idx = 0; idx < test_node_list[0].size; idx++)
		strcpy(node_pattern[num_patterns++], test_node_list[0].nodes[idx]);
}
int
validate_node_names(uint64_t *valid_nodes)
{
	rte_node_t node_cnt = rte_node_max_count();
	bool pattern_matched = false;
	rte_node_t id = 0;
	int ret = -EINVAL;
	uint16_t idx, i, j;

	for (idx = 0; idx < num_patterns; idx++) {
		for (id = 0; id < node_cnt; id++) {
			if (strncmp(node_pattern[idx], rte_node_id_to_name(id),
				    RTE_GRAPH_NAMESIZE) == 0)
				break;
		}
		if (node_cnt == id) {
			printf("Invalid node name passed\n");
			return ret;
		}
	}

	printf("num_ptrn:: %u\n", num_patterns);
	for (i = 0; i < RTE_DIM(test_node_list); i++) {
		idx = 0;
		if (test_node_list[i].size == num_patterns) {
			for (j = 0; j < num_patterns; j++) {
				if (strncmp(node_pattern[j], test_node_list[i].nodes[j],
				    RTE_GRAPH_NAMESIZE) == 0)
					idx++;
			}
			printf("idx::%u\n", idx);
			if (idx == num_patterns)
				pattern_matched = true;
		}
	}

	if (!pattern_matched) {
		printf("Unsupported node pattern passed\n\n");
		printf("Test supported node patterns are:\n");
		for (i = 0; i < RTE_DIM(test_node_list); i++) {
			printf("(");
			for (j = 0; j < (test_node_list[i].size - 1); j++)
				printf("%s,", test_node_list[i].nodes[j]);
			printf("%s", test_node_list[i].nodes[j]);
			printf(")\n");
		}

		return ret;
	}

	for (i = 0; i < RTE_DIM(supported_nodes); i++) {
		for (j = 0; j < num_patterns; j++) {
			if (strncmp(node_pattern[j], supported_nodes[i].nodes[0],
				    RTE_GRAPH_NAMESIZE) == 0) {
				*valid_nodes |= supported_nodes[i].test_id;
				break;
			}
		}
	}

	return 0;
}

void
cleanup_node_pattern(void)
{
	while (num_patterns) {
		memset(node_pattern[num_patterns - 1], 0, RTE_GRAPH_NAMESIZE);
		num_patterns--;
	}
}

static int
ethdev_tx_node_configure(struct rte_node_ethdev_config *conf, uint16_t nb_confs)
{
	struct ethdev_tx_node_main *tx_node_data;
	struct rte_node_register *tx_node;
	char name[RTE_NODE_NAMESIZE];
	uint16_t port_id;
	uint32_t id;
	int i;

	tx_node_data = ethdev_tx_node_data_get();
	tx_node = ethdev_tx_node_get();

	for (i = 0; i < nb_confs; i++) {
		port_id = conf[i].port_id;

		if (!rte_eth_dev_is_valid_port(port_id))
			return -EINVAL;

		/* Create a per port tx node from base node */
		snprintf(name, sizeof(name), "%u", port_id);
		id = rte_node_clone(tx_node->id, name);
		tx_node_data->nodes[port_id] = id;

		printf("ethdev:: Tx node %s-%s: is at %u\n", tx_node->name, name, id);
	}

	return 0;
}

static int
punt_kernel_node_configure(void)
{
	struct rte_node_register *punt_node;
	char name[RTE_NODE_NAMESIZE];
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint32_t id;

	punt_node = punt_kernel_node_get();

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		/* Create a per lcore punt_kernel node from base node */
		snprintf(name, sizeof(name), "%u", lcore_id);
		id = rte_node_clone(punt_node->id, name);
		strcpy(qconf->punt_kernel_node_name, rte_node_id_to_name(id));

		printf("punt_kernel node %s-%s: is at %u\n", punt_node->name, name, id);
	}

	return 0;
}

static int
ethdev_rx_node_configure(struct rte_node_ethdev_config *conf, uint16_t nb_confs)
{
	char name[RTE_NODE_NAMESIZE];
	uint16_t i, j, port_id;
	uint32_t id;

	for (i = 0; i < nb_confs; i++) {
		port_id = conf[i].port_id;

		if (!rte_eth_dev_is_valid_port(port_id))
			return -EINVAL;

		/* Create node for each rx port queue pair */
		for (j = 0; j < conf[i].num_rx_queues; j++) {
			struct ethdev_rx_node_main *rx_node_data;
			struct rte_node_register *rx_node;
			ethdev_rx_node_elem_t *elem;

			rx_node_data = ethdev_rx_get_node_data_get();
			rx_node = ethdev_rx_node_get();
			snprintf(name, sizeof(name), "%u-%u", port_id, j);
			/* Clone a new rx node with same edges as parent */
			id = rte_node_clone(rx_node->id, name);
			if (id == RTE_NODE_ID_INVALID)
				return -EIO;

			/* Add it to list of ethdev rx nodes for lookup */
			elem = malloc(sizeof(ethdev_rx_node_elem_t));
			if (elem == NULL)
				return -ENOMEM;
			memset(elem, 0, sizeof(ethdev_rx_node_elem_t));
			elem->ctx.port_id = port_id;
			elem->ctx.queue_id = j;
			elem->nid = id;
			elem->next = rx_node_data->head;
			rx_node_data->head = elem;

			printf("ethdev:: Rx node %s-%s: is at %u\n", rx_node->name, name, id);
		}
	}

	return 0;
}

static int
update_ethdev_rx_node_next(rte_node_t id, const char *edge_name)
{
	struct ethdev_rx_node_main *rx_node_data;
	ethdev_rx_node_elem_t *elem;
	char *next_nodes[16];
	rte_edge_t count;
	uint16_t i;

	count = rte_node_edge_count(id);
	rte_node_edge_get(id, next_nodes);

	for (i = 0; i < count; i++) {
		if (fnmatch(edge_name, next_nodes[i], 0) == 0) {
			rx_node_data = ethdev_rx_get_node_data_get();
			elem = rx_node_data->head;
			while (elem->next != rx_node_data->head) {
				if (elem->nid == id)
					break;
				elem = elem->next;
			}

			if (elem->nid == id)
				elem->ctx.cls_next = i;
			break;
		}
	}

	return 0;
}

static int
link_ethdev_rx_to_tx_node(struct rte_node_ethdev_config *conf, uint16_t nb_confs)
{
	const char * const pattern[] = {"ethdev_tx-*"};
	char name[RTE_NODE_NAMESIZE];
	const char *next_node = name;
	uint16_t i, j, port_id;
	uint32_t rx_id;

	for (i = 0; i < nb_confs; i++) {
		port_id = conf[i].port_id;

		if (!rte_eth_dev_is_valid_port(port_id))
			return -EINVAL;

		for (j = 0; j < conf[i].num_rx_queues; j++) {

			snprintf(name, sizeof(name), "ethdev_rx-%u-%u", port_id, j);
			rx_id = rte_node_from_name(name);

			/* Fill node pattern */
			strcpy(node_pattern[num_patterns++], name);

			/* Prepare the actual name of the cloned node */
			snprintf(name, sizeof(name), "ethdev_tx-%u", port_id);

			/* Update ethdev_rx node edges */
			rte_node_edge_update(rx_id, RTE_EDGE_ID_INVALID, &next_node, 1);

			/* Fill node pattern */
			strcpy(node_pattern[num_patterns++], name);

			/* Update node_next details */
			update_ethdev_rx_node_next(rx_id, pattern[0]);
		}
	}

	return 0;
}

static int
link_ethdev_rx_to_punt_kernel_node(void)
{
	uint16_t queueid, portid, queue;
	char name[RTE_NODE_NAMESIZE];
	const char *next_node = name;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	rte_node_t rx_id;
	const char * const pattern[] = {"punt_kernel-*"};

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {

			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			snprintf(name, sizeof(name), "ethdev_rx-%u-%u", portid, queueid);
			rx_id = rte_node_from_name(name);

			/* Fill node pattern */
			strcpy(node_pattern[num_patterns++], name);

			next_node = qconf->punt_kernel_node_name;

			/* Fill node pattern */
			strcpy(node_pattern[num_patterns++], next_node);

			/* Update ethdev_rx node edges */
			rte_node_edge_update(rx_id, RTE_EDGE_ID_INVALID, &next_node, 1);

			/* Update node_next details */
			update_ethdev_rx_node_next(rx_id, pattern[0]);
		}
	}

	return 0;
}

uint32_t
ethdev_ports_setup(void)
{
	struct rte_eth_dev_info dev_info;
	uint32_t nb_tx_queue, nb_lcores;
	uint32_t nb_ports, nb_conf = 0;
	uint8_t nb_rx_queue;
	uint16_t portid;
	int ret;

	nb_ports = rte_eth_dev_count_avail();
	nb_lcores = rte_lcore_count();

	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_conf local_port_conf = port_conf;

		/* Skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			continue;
		}

		/* Init port */
		printf("Initializing port %d ... ", portid);
		fflush(stdout);

		nb_rx_queue = get_port_n_rx_queues(portid);
		nb_tx_queue = nb_lcores;
		if (nb_tx_queue > MAX_TX_QUEUE_PER_PORT)
			nb_tx_queue = MAX_TX_QUEUE_PER_PORT;
		printf("Creating queues: nb_rxq=%d nb_txq=%u...\n", nb_rx_queue, nb_tx_queue);

		rte_eth_dev_info_get(portid, &dev_info);

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
		    port_conf.rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function based on hardware support,"
			       "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
			       portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
			       local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret,
				 portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d,"
				 "port=%d\n",
				 ret, portid);

		/* Init memory */
		if (!per_port_pool)
			ret = init_mem(0, NB_MBUF(nb_ports));
		else
			ret = init_mem(portid, NB_MBUF(1));

		if (ret < 0)
			rte_exit(EXIT_FAILURE, "init_mem() failed\n");

		/* Setup ethdev node config */
		ethdev_conf[nb_conf].port_id = portid;
		ethdev_conf[nb_conf].num_rx_queues = nb_rx_queue;
		ethdev_conf[nb_conf].num_tx_queues = nb_tx_queue;
		if (!per_port_pool)
			ethdev_conf[nb_conf].mp = pktmbuf_pool[0];

		else
			ethdev_conf[nb_conf].mp = pktmbuf_pool[portid];
		ethdev_conf[nb_conf].mp_count = NB_SOCKETS;

		nb_conf++;
	}

	return nb_conf;
}

void
ethdev_rxq_configure(void)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queueid, portid;
	struct lcore_conf *qconf;
	uint8_t queue, socketid;
	uint32_t lcore_id;
	int ret;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];
		printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
		fflush(stdout);

		/* Init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			struct rte_eth_rxconf rxq_conf;

			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			if (numa_on)
				socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("rxq=%d,%d,%d ", portid, queueid, socketid);
			fflush(stdout);

			rte_eth_dev_info_get(portid, &dev_info);
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port_conf.rxmode.offloads;
			if (!per_port_pool)
				ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
							     &rxq_conf, pktmbuf_pool[0][socketid]);
			else
				ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
							     &rxq_conf,
							     pktmbuf_pool[portid][socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n",
					 ret, portid);

			snprintf(qconf->rx_queue_list[queue].node_name, RTE_NODE_NAMESIZE,
				 "ethdev_rx-%u-%u", portid, queueid);
		}
	}
	printf("\n");
}

void
ethdev_txq_configure(void)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t queueid, portid;
	uint32_t lcore_id;
	uint8_t socketid;
	int ret;

	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_conf local_port_conf = port_conf;

		/* Skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			continue;
		}

		rte_eth_dev_info_get(portid, &dev_info);

		/* Init one TX queue per (lcore,port) pair */
		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			if (numa_on)
				socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n",
					 ret, portid);
			queueid++;
		}
	}
	printf("\n");
}

int
configure_graph_nodes(uint64_t valid_nodes)
{
	int ret = 0;

	if (valid_nodes & TEST_GRAPH_ETHDEV_RX_NODE) {
		ret = ethdev_rx_node_configure(ethdev_conf, nb_conf);
		if (ret) {
			printf("ethdev_rx_node_configure: err=%d\n", ret);
			goto exit;
		}
	}

	if (valid_nodes & TEST_GRAPH_ETHDEV_TX_NODE) {
		ret = ethdev_tx_node_configure(ethdev_conf, nb_conf);
		if (ret) {
			printf("ethdev_tx_node_configure: err=%d\n", ret);
			goto exit;
		}
	}

	if (valid_nodes & TEST_GRAPH_PUNT_KERNEL_NODE) {
		ret = punt_kernel_node_configure();
		if (ret) {
			printf("punt_kernel_node_configure: err=%d\n", ret);
			goto exit;
		}
	}

	cleanup_node_pattern();

	if (valid_nodes == (TEST_GRAPH_ETHDEV_TX_NODE | TEST_GRAPH_ETHDEV_RX_NODE)) {
		ret = link_ethdev_rx_to_tx_node(ethdev_conf, nb_conf);
		if (ret) {
			printf("link_ethdev_rx_to_tx_node: err=%d\n", ret);
			goto exit;
		}
	} else if (valid_nodes == (TEST_GRAPH_ETHDEV_RX_NODE | TEST_GRAPH_PUNT_KERNEL_NODE)) {
		link_ethdev_rx_to_punt_kernel_node();
	} else {
		printf("Invalid node map\n");
		ret = -EINVAL;
	}

exit:
	return ret;
}

void
start_eth_ports(void)
{
	uint16_t portid;
	int ret;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, portid);

		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}
}

void
stop_eth_ports(void)
{
	uint16_t portid;
	int ret;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("Failed to stop port %u: %s\n", portid, rte_strerror(-ret));
		rte_eth_dev_close(portid);
	}
}

int
create_graph(char pattern[][RTE_NODE_NAMESIZE], uint8_t num_patterns)
{
	struct rte_graph_param graph_conf;
	struct lcore_conf *qconf;
	uint32_t lcore_id;

	node_patterns = malloc(MAX_NODE_PATTERNS * sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;

	memset(&graph_conf, 0, sizeof(graph_conf));
	graph_conf.node_patterns = node_patterns;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rte_graph_t graph_id;
		rte_edge_t i;

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		/* Skip graph creation if no source exists */
		if (!qconf->n_rx_queue)
			continue;

		for (i = 0; i < num_patterns; i++)
			graph_conf.node_patterns[i] = pattern[i];

		graph_conf.nb_node_patterns = num_patterns;

		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		snprintf(qconf->name, sizeof(qconf->name), "worker_%u", lcore_id);

		graph_id = rte_graph_create(qconf->name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID)
			rte_exit(EXIT_FAILURE, "rte_graph_create(): graph_id invalid for lcore%u\n",
				 lcore_id);

		qconf->graph_id = graph_id;
		qconf->graph = rte_graph_lookup(qconf->name);

		if (!qconf->graph)
			rte_exit(EXIT_FAILURE, "rte_graph_lookup(): graph %s not found\n",
				 qconf->name);
	}

	return 0;
}

int
destroy_graph(void)
{
	uint32_t lcore_id;
	rte_graph_t id;
	int ret;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (lcore_conf[lcore_id].graph) {
			id = rte_graph_from_name(lcore_conf[lcore_id].name);
			if (rte_graph_destroy(id)) {
				printf("graph_id %u destroy failed.\n", id);
				ret = -1;
			}
		}
	}

	if (node_patterns)
		free(node_patterns);

	return ret;
}

int
main(int argc, char **argv)
{
	uint64_t valid_nodes;
	uint32_t lcore_id;
	int ret;

	graph_walk_quit = false;
	force_quit = false;
	interactive = 0;

	node_patterns = NULL;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	testgraph_logtype = rte_log_register("testgraph");
	if (testgraph_logtype < 0)
		rte_exit(EXIT_FAILURE, "Cannot register log type");

	set_default_node_pattern();

	rte_log_set_level(testgraph_logtype, RTE_LOG_DEBUG);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL: %s\n", rte_strerror(rte_errno));
	argc -= ret;
	argv += ret;

	if (argc > 1) {
		ret = parse_cmdline_args(argc, argv);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Invalid command line parameters\n");
	}

#ifdef RTE_LIB_CMDLINE
	if (init_cmdline() != 0)
		rte_exit(EXIT_FAILURE, "Could not initialise cmdline context.\n");

	if (interactive == 1) {
		prompt();
	} else
#endif
	{
		if (validate_config() < 0)
			rte_exit(EXIT_FAILURE, "Config validation failed.\n");

		ret = validate_node_names(&valid_nodes);
		if (ret)
			rte_exit(EXIT_FAILURE, "validate_node_names: err=%d\n", ret);

		nb_conf = ethdev_ports_setup();

		ethdev_rxq_configure();

		ethdev_txq_configure();

		ret = configure_graph_nodes(valid_nodes);
		if (ret)
			rte_exit(EXIT_FAILURE, "configure_graph_nodes: err=%d\n", ret);

		start_eth_ports();

		check_all_ports_link_status(enabled_port_mask);

		ret = create_graph(node_pattern, num_patterns);
		if (ret)
			rte_exit(EXIT_FAILURE, "create_graph: err=%d\n", ret);

		stats = create_graph_cluster_stats();
		if (stats == NULL)
			rte_exit(EXIT_FAILURE, "create_graph_cluster_stats() failed\n");

		/* Launch per-lcore init on every worker lcore */
		rte_eal_mp_remote_launch(graph_main_loop, NULL, SKIP_MAIN);

		/* Accumulate and print stats on main until exit */
		if (rte_graph_has_stats_feature())
			print_stats();

		/* Wait for worker cores to exit */
		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			ret = rte_eal_wait_lcore(lcore_id);
			if (ret < 0)
				break;
		}

		ret = destroy_graph();

		stop_eth_ports();
	}

	/* clean up the EAL */
	ret = rte_eal_cleanup();
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "EAL cleanup failed: %s\n", strerror(-ret));

	return EXIT_SUCCESS;
}

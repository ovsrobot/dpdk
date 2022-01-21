/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_gen.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define MIN_THREADS 3

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_lro_pkt_size = RTE_ETHER_MAX_LEN,
	},
};

static volatile int done;
static struct rte_mempool *mbuf_pool;
struct rte_gen *gen;

static void handle_sigint(int sig);

/* Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	int lcore_available_count = rte_lcore_count();
	if (lcore_available_count < MIN_THREADS) {
		printf("Not enough threads available\n");
		return -1;
	}

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

/* The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static int
lcore_producer(__rte_unused void *arg)
{
	uint16_t port;

	/* Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	/* Run until the application is quit or killed. */
	while (!done) {
		struct rte_mbuf *bufs[BURST_SIZE];
		int i;
		/* Receive packets from gen and then tx them over port */
		RTE_ETH_FOREACH_DEV(port) {
			int nb_recieved = rte_gen_rx_burst(gen, bufs,
							BURST_SIZE);
			for (i = 0; i < nb_recieved; i++) {
				bufs[i]->pkt_len = 64;
				bufs[i]->data_len = 64;
			}

			uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs,
							nb_recieved);
			if (nb_tx != nb_recieved)
				rte_pktmbuf_free_bulk(&bufs[nb_tx],
							(nb_recieved - nb_tx));

			if (unlikely(nb_tx == 0))
				continue;

		}
	}
	return 0;
}

/* The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static int
lcore_consumer(__rte_unused void *arg)
{
	uint16_t port;

	/* Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	/* Run until the application is quit or killed. */
	while (!done) {
		struct rte_mbuf *bufs[BURST_SIZE];

		/* Receive packets over port and then tx them to gen library
		 * for stats
		 */
		RTE_ETH_FOREACH_DEV(port) {
			uint64_t latency[BURST_SIZE];
			uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs,
							BURST_SIZE);
			rte_gen_tx_burst(gen, bufs, latency, nb_rx);

			int nb_sent = rte_gen_tx_burst(gen, bufs,
							latency, nb_rx);
			if (nb_sent != nb_rx)
				rte_panic("invalid tx quantity\n");

			if (unlikely(nb_rx == 0))
				continue;

		}
	}
	return 0;
}

void handle_sigint(int sig)
{
	RTE_SET_USED(sig);
	printf("\nExiting...\n");
	done = 1;
}

/* The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	signal(SIGINT, handle_sigint);
	unsigned int nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	gen = rte_gen_create(mbuf_pool);
	if (!gen)
		rte_panic("Gen failed to initialize\n");

	int err = rte_gen_packet_parse_string(gen, "Ether()/IP()", NULL);
	if (err)
		rte_panic("Failed to parse input args");

	/* launch lcore functions */
	uint32_t lcore_count = 0;
	uint32_t lcore_id = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (lcore_count == 0)
			rte_eal_remote_launch(lcore_producer, NULL, lcore_id);
		else if (lcore_count == 1)
			rte_eal_remote_launch(lcore_consumer, NULL, lcore_id);
		else
			break;

		lcore_count++;
	}
	/* Stall the main thread until all other threads have returned. */
	rte_eal_mp_wait_lcore();

	/* All threads returned, safe to destroy gen instance */
	rte_gen_destroy(gen);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

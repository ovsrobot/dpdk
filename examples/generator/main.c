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
#include <rte_telemetry.h>

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
	.intr_conf = {
		.lsc = 1, /**< lsc interrupt */
	},
};

static volatile int done;
static volatile int link_status[RTE_MAX_ETHPORTS];
static struct rte_mempool *mbuf_pool;
struct rte_gen *gen;

struct gen_args {
	/* Inputs */
	struct rte_gen *gen;

	/* Outputs */
	uint64_t tx_total_packets;
	uint64_t rx_total_packets;
	uint64_t rx_missed_total;
	uint64_t tx_failed;
	uint64_t last_tx_total;
	uint64_t measured_tx_pps;
} __rte_cache_aligned;
/* Expose a struct as a global so the telemetry callbacks can access the
 * data required to provide stats etc.
 */
struct telemetry_userdata {
	struct gen_args *prod;
	struct gen_args *cons;
};
static struct telemetry_userdata telemetry_userdata;

static void handle_sigint(int sig);

static int
link_status_change_cb(uint16_t port_id, enum rte_eth_event_type type,
		      void *param, void *ret_param)
{
	if (unlikely(port_id >= RTE_DIM(link_status)))
		rte_panic("got LSC interrupt for unknown port id\n");

	RTE_SET_USED(type);
	RTE_SET_USED(param);
	RTE_SET_USED(ret_param);

	struct rte_eth_link link;
	int ret = rte_eth_link_get_nowait(port_id, &link);
	if (ret < 0) {
		printf("Failed link get on port %d: %s\n",
		       port_id, rte_strerror(-ret));
		return ret;
	}

	printf("Link status change port %i\n", port_id);
	link_status[port_id] = link.link_status;
	return 0;
}

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
	/* Register the LinkStatusChange callback */
	rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC,
				      link_status_change_cb, NULL);

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

	struct rte_eth_link link;
	int ret = rte_eth_link_get_nowait(port, &link);
	if (ret < 0) {
		printf("Failed link get on port %d: %s\n", port,
							rte_strerror(-ret));
		return ret;
	}

	link_status[port] = link.link_status;

	return 0;
}

static void
gen_wait_for_links_up(void)
{
	/* Ensure all available ports are up before generating packets */
	uint16_t nb_eth_ports = rte_eth_dev_count_avail();
	uint16_t nb_links_up = 0;
	while (!done && nb_links_up < nb_eth_ports) {
		if (link_status[nb_links_up])
			nb_links_up++;

		rte_delay_us_block(100);
	}
}

/* The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static int
lcore_producer(void *arg)
{
	struct gen_args *args = arg;
	struct rte_gen *gen = args->gen;
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

	uint64_t tsc_hz = rte_get_tsc_hz();
	uint64_t last_tsc_reading = 0;
	uint64_t last_tx_total = 0;
	uint16_t nb_tx = 0;

	/* Wait for links to come up before generating packets */
	gen_wait_for_links_up();
	if (!done)
		printf("Generating packets...\n");

	/* Run until the application is quit or killed. */
	while (!done) {

		struct rte_mbuf *bufs[BURST_SIZE];
		/* Receive packets from gen and then tx them over port */

		RTE_ETH_FOREACH_DEV(port) {
			int nb_generated = rte_gen_rx_burst(gen, bufs,
							BURST_SIZE);

			uint64_t start_tsc = rte_rdtsc();
			if (start_tsc > last_tsc_reading + tsc_hz) {
				args->measured_tx_pps = args->tx_total_packets -
								last_tx_total;
				last_tx_total = args->tx_total_packets;
				last_tsc_reading = start_tsc;
			}
			nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_generated);
			args->tx_total_packets += nb_tx;

			uint64_t tx_failed = nb_generated - nb_tx;
			if (nb_tx != nb_generated) {
				rte_pktmbuf_free_bulk(&bufs[nb_tx], tx_failed);
				args->tx_failed += tx_failed;
			}
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
lcore_consumer(void *arg)
{
	struct gen_args *args = arg;
	struct rte_gen *gen = args->gen;
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

	/* Wait for links to come up before generating packets */
	gen_wait_for_links_up();

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
			if (unlikely(nb_rx == 0))
				continue;

			args->rx_total_packets += nb_rx;

			int nb_sent = rte_gen_tx_burst(gen, bufs,
							latency, nb_rx);
			if (nb_sent != nb_rx)
				rte_panic("invalid tx quantity\n");

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

static int
tele_gen_mpps(const char *cmd, const char *params, struct rte_tel_data *d)
{
	RTE_SET_USED(cmd);
	RTE_SET_USED(params);

	struct gen_args *args = telemetry_userdata.prod;
	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_int(d, "pps",
					(args->measured_tx_pps));
	return 0;
}

static int
tele_gen_stats(const char *cmd, const char *params, struct rte_tel_data *d)
{
	RTE_SET_USED(cmd);
	RTE_SET_USED(params);

	struct gen_args *args_prod = telemetry_userdata.prod;
	struct gen_args *args_cons = telemetry_userdata.cons;
	rte_tel_data_start_dict(d);
	static const char * const stats[] = {
		"tx_total_packets",
		"rx_total_packets",
		"measured_tx_pps"
	};

	uint64_t values[RTE_DIM(stats)] = {0};
	values[0] = args_prod->tx_total_packets;
	values[1] = args_cons->rx_total_packets;
	values[2] = args_prod->measured_tx_pps;

	uint32_t i;
	for (i = 0; i < RTE_DIM(stats); i++)
		rte_tel_data_add_dict_int(d, stats[i], values[i]);

	return 0;
}
/* The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	signal(SIGINT, handle_sigint);

	#define CORE_COUNT 2
	struct gen_args core_launch_args[CORE_COUNT];

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

	struct rte_gen *gen = rte_gen_create(mbuf_pool);
	if (!gen)
		rte_panic("Gen failed to initialize\n");

	int err = rte_gen_packet_parse_string(gen, "Ether()/IP()", NULL);
	if (err)
		rte_panic("Failed to parse input args");

	memset(core_launch_args, 0, sizeof(struct gen_args) * CORE_COUNT);
	/* launch lcore functions */
	uint32_t lcore_count = 0;
	uint32_t lcore_id = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		core_launch_args[lcore_count].gen = gen;
		if (lcore_count == 0) {
			telemetry_userdata.prod =
						&core_launch_args[lcore_count];
			rte_eal_remote_launch(lcore_producer,
					      telemetry_userdata.prod,
					      lcore_id);
		} else if (lcore_count == 1) {
			telemetry_userdata.cons =
						&core_launch_args[lcore_count];
			rte_eal_remote_launch(lcore_consumer,
					      telemetry_userdata.cons,
					      lcore_id);
		}
		else
			break;

		lcore_count++;
	}

	/* Export stats via Telemetry */
	rte_telemetry_register_cmd("/gen/stats", tele_gen_stats,
			"Return statistics of the Gen instance.");
	rte_telemetry_register_cmd("/gen/mpps", tele_gen_mpps,
			"Get/Set the mpps rate");

	/* Stall the main thread until all other threads have returned. */
	rte_eal_mp_wait_lcore();

	/* All threads returned, safe to destroy gen instance */
	rte_gen_destroy(gen);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

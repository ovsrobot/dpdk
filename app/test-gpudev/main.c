/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>

#include <rte_gpudev.h>

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&x)
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (ACCESS_ONCE(x) = (v))
#endif

#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    (1UL << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)

#define MAX_QUEUES 16
#define NUM_COMM_ITEMS 2048
#define PKT_GAP 4

// #define DEBUG_PRINT 1

enum app_args {
	ARG_HELP,
	ARG_BURST,
	ARG_GPU,
	ARG_MBUFD,
	ARG_MEMORY,
	ARG_QUEUES,
	ARG_TESTAPI,
};

enum mem_type {
	MEMORY_CPU,
	MEMORY_GPU
};

/* Options configurable from cmd line */
static uint32_t conf_burst = 64;
static uint16_t conf_gpu_id = 0;
static enum mem_type conf_mtype = MEMORY_CPU;
static uint32_t conf_mbuf_dataroom = 2048;
static uint32_t conf_queues = 1;
static bool conf_testapi = false;
static uint16_t conf_nb_descriptors = 2048;

/* Options statically defined */
static uint32_t conf_nb_mbuf = 16384;
static uint16_t conf_port_id = 0;

/* Other variables */
static volatile bool force_quit;
static struct rte_mempool *mpool;
static struct rte_pktmbuf_extmem ext_mem;
struct rte_gpu_comm_list *comm_list_fwd[MAX_QUEUES];
struct rte_ether_addr port_eth_addr;
static struct rte_eth_conf port_conf = {
	.rxmode = {
				.mq_mode = ETH_MQ_RX_RSS,
				.split_hdr_size = 0,
				.offloads = 0,
			},
	.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
			.offloads = 0,
			},
	.rx_adv_conf = {
			.rss_conf = {
						.rss_key = NULL,
						.rss_hf = ETH_RSS_IP
					},
			},
};

static void
usage(const char *prog_name)
{
	printf("%s [EAL options] --\n"
		" --help\n"
		" --burst N: number of packets per rx burst\n"
		" --gpu N: GPU ID to use\n"
		" --memory N: external mempool memory type, 0 CPU, 1 GPU\n"
		" --mbufd N: mbuf dataroom size\n"
		" --testapi: test gpudev function\n"
		" --queues N: number of RX queues\n",
		prog_name);
}

static int
args_parse(int argc, char **argv)
{
	char **argvopt;
	int opt;
	int opt_idx;

	static struct option lgopts[] = {
		{ "help",  0, 0, ARG_HELP},
		/* Packets per burst. */
		{ "burst",  1, 0, ARG_BURST},
		/* GPU to use. */
		{ "gpu",  1, 0, ARG_GPU},
		/* Type of memory for the mempool. */
		{ "memory",  1, 0, ARG_MEMORY},
		/* Size of mbufs dataroom */
		{ "mbufd", 1, 0, ARG_MBUFD},
		/* Number of RX queues */
		{ "queues", 1, 0, ARG_QUEUES},
		/* Test only gpudev functions */
		{ "testapi", 0, 0, ARG_TESTAPI},
		/* End of options */
		{ 0, 0, 0, 0 }
	};

	argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case ARG_BURST:
			conf_burst = (uint32_t) atoi(optarg);
			break;
		case ARG_GPU:
			conf_gpu_id = (uint16_t) atoi(optarg);
			break;
		case ARG_MEMORY:
			conf_mtype = (atoi(optarg) == 1 ? MEMORY_GPU : MEMORY_CPU);
			break;
		case ARG_MBUFD:
			conf_mbuf_dataroom = (uint32_t) atoi(optarg);
			break;
		case ARG_QUEUES:
			conf_queues = (uint32_t) atoi(optarg);
			break;
		case ARG_TESTAPI:
			conf_testapi = (atoi(optarg) == 1 ? true : false);
			break;
		case ARG_HELP:
			usage(argv[0]);
			break;
		default:
			usage(argv[0]);
			rte_exit(EXIT_FAILURE, "Invalid option: %s\n", argv[optind]);
			break;
		}
	}

	if (conf_queues > MAX_QUEUES) {
		fprintf(stderr, "Can't support more than %d queues\n", MAX_QUEUES);
		return -1;
	}

	if (conf_queues * 2 > rte_lcore_count()) {
		fprintf(stderr,
				"Need to use at least %d cores to support %d RX/TX queues (EAL cores %d)\n",
				conf_queues * 2, conf_queues, rte_lcore_count());
		return -1;
	}

	return 0;
}

static int
alloc_gpu_memory(uint16_t gpu_id)
{
	void *ptr_1 = NULL;
	void *ptr_2 = NULL;
	size_t buf_bytes = 1024;
	int ret;

	printf("\n=======> TEST: Allocate GPU memory\n\n");

	/* Alloc memory on GPU 0 */
	ptr_1 = rte_gpu_mem_alloc(gpu_id, buf_bytes);
	if (ptr_1 == NULL) {
		fprintf(stderr, "rte_gpu_mem_alloc GPU memory returned error\n");
		goto error;
	}
	printf("GPU memory allocated at 0x%p size is %zd bytes\n",
			ptr_1, buf_bytes);

	ptr_2 = rte_gpu_mem_alloc(gpu_id, buf_bytes);
	if (ptr_2 == NULL) {
		fprintf(stderr, "rte_gpu_mem_alloc GPU memory returned error\n");
		goto error;
	}
	printf("GPU memory allocated at 0x%p size is %zd bytes\n",
			ptr_2, buf_bytes);

	ret = rte_gpu_mem_free(gpu_id, (uint8_t *)(ptr_1)+0x700);
	if (ret < 0) {
		printf("GPU memory 0x%p NOT freed: GPU driver didn't find this memory address internally.\n",
				(uint8_t *)(ptr_1)+0x700);
	} else {
		fprintf(stderr, "ERROR: rte_gpu_mem_free freed GPU memory 0x%p\n",
				(uint8_t *)(ptr_1)+0x700);
		goto error;
	}

	ret = rte_gpu_mem_free(gpu_id, ptr_2);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_mem_free returned error %d\n", ret);
		goto error;
	}
	printf("GPU memory 0x%p freed\n", ptr_2);

	ret = rte_gpu_mem_free(gpu_id, ptr_1);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_mem_free returned error %d\n", ret);
		goto error;
	}
	printf("GPU memory 0x%p freed\n", ptr_1);

	printf("\n=======> TEST: PASSED\n");
	return 0;

error:
	printf("\n=======> TEST: FAILED\n");
	return -1;
}

static int
register_cpu_memory(uint16_t gpu_id)
{
	void *ptr = NULL;
	size_t buf_bytes = 1024;
	int ret;

	printf("\n=======> TEST: Register CPU memory\n\n");

	/* Alloc memory on CPU visible from GPU 0 */
	ptr = rte_zmalloc(NULL, buf_bytes, 0);
	if (ptr == NULL) {
		fprintf(stderr, "Failed to allocate CPU memory.\n");
		goto error;
	}

	ret = rte_gpu_mem_register(gpu_id, buf_bytes, ptr);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_mem_register CPU memory returned error %d\n", ret);
		goto error;
	}
	printf("CPU memory registered at 0x%p %zdB\n", ptr, buf_bytes);

	ret = rte_gpu_mem_unregister(gpu_id, (uint8_t *)(ptr)+0x700);
	if (ret < 0) {
		printf("CPU memory 0x%p NOT unregistered: GPU driver didn't find this memory address internally\n",
				(uint8_t *)(ptr)+0x700);
	} else {
		fprintf(stderr, "ERROR: rte_gpu_mem_unregister unregistered GPU memory 0x%p\n",
				(uint8_t *)(ptr)+0x700);
		goto error;
	}

	ret = rte_gpu_mem_unregister(gpu_id, ptr);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_mem_unregister returned error %d\n", ret);
		goto error;
	}
	printf("CPU memory 0x%p unregistered\n", ptr);

	printf("\n=======> TEST: PASSED\n");
	return 0;

error:
	printf("\n=======> TEST: FAILED\n");
	return -1;
}

static int
create_update_comm_flag(uint16_t gpu_id)
{
	struct rte_gpu_comm_flag devflag;
	int ret = 0;
	uint32_t set_val;
	uint32_t get_val;

	printf("\n=======> TEST: Communication flag\n\n");

	ret = rte_gpu_comm_create_flag(gpu_id, &devflag, RTE_GPU_COMM_FLAG_CPU);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_create_flag returned error %d\n", ret);
		goto error;
	}

	set_val = 25;
	ret = rte_gpu_comm_set_flag(&devflag, set_val);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_set_flag returned error %d\n", ret);
		goto error;
	}

	ret = rte_gpu_comm_get_flag_value(&devflag, &get_val);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_get_flag_value returned error %d\n", ret);
		goto error;
	}

	printf("Communication flag value at 0x%p was set to %d and current value is %d\n",
			devflag.ptr, set_val, get_val);

	set_val = 38;
	ret = rte_gpu_comm_set_flag(&devflag, set_val);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_set_flag returned error %d\n", ret);
		goto error;
	}

	ret = rte_gpu_comm_get_flag_value(&devflag, &get_val);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_get_flag_value returned error %d\n", ret);
		goto error;
	}

	printf("Communication flag value at 0x%p was set to %d and current value is %d\n",
			devflag.ptr, set_val, get_val);

	ret = rte_gpu_comm_destroy_flag(&devflag);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_destroy_flags returned error %d\n", ret);
		goto error;
	}

	printf("\n=======> TEST: PASSED\n");
	return 0;

error:
	printf("\n=======> TEST: FAILED\n");
	return -1;
}

static int
simulate_gpu_task(struct rte_gpu_comm_list *comm_list_item, int num_pkts)
{
	int idx;

	if (comm_list_item == NULL)
		return -1;

	for (idx = 0; idx < num_pkts; idx++) {
		/**
		 * consume(comm_list_item->pkt_list[idx].addr);
		 */
	}
	comm_list_item->status = RTE_GPU_COMM_LIST_DONE;

	return 0;
}

static int
create_update_comm_list(uint16_t gpu_id)
{
	int ret = 0;
	int i = 0;
	struct rte_gpu_comm_list *comm_list;
	uint32_t num_comm_items = 1024;
	struct rte_mbuf *mbufs[10];

	printf("\n=======> TEST: Communication list\n\n");

	comm_list = rte_gpu_comm_create_list(gpu_id, num_comm_items);
	if (comm_list == NULL) {
		fprintf(stderr, "rte_gpu_comm_create_list returned error %d\n", ret);
		goto error;
	}

	/**
	 * Simulate DPDK receive functions like rte_eth_rx_burst()
	 */
	for (i = 0; i < 10; i++) {
		mbufs[i] = rte_zmalloc(NULL, sizeof(struct rte_mbuf), 0);
		if (mbufs[i] == NULL) {
			fprintf(stderr, "Failed to allocate fake mbufs in CPU memory.\n");
			goto error;
		}

		memset(mbufs[i], 0, sizeof(struct rte_mbuf));
	}

	/**
	 * Populate just the first item of  the list
	 */
	ret = rte_gpu_comm_populate_list_pkts(&(comm_list[0]), mbufs, 10);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_populate_list_pkts returned error %d\n", ret);
		goto error;
	}

	ret = rte_gpu_comm_cleanup_list(&(comm_list[0]));
	if (ret == 0) {
		fprintf(stderr, "rte_gpu_comm_cleanup_list erroneously cleaned the list even if packets have not been consumed yet\n");
		goto error;
	}
	printf("Communication list not cleaned because packets have not been consumed yet.\n");

	/**
	 * Simulate a GPU tasks going through the packet list to consume
	 * mbufs packets and release them
	 */
	printf("Consuming packets...\n");
	simulate_gpu_task(&(comm_list[0]), 10);

	/**
	 * Packets have been consumed, now the communication item
	 * and the related mbufs can be all released
	 */
	ret = rte_gpu_comm_cleanup_list(&(comm_list[0]));
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_cleanup_list returned error %d\n", ret);
		goto error;
	}

	printf("Communication list cleaned because packets have been consumed now.\n");

	ret = rte_gpu_comm_destroy_list(comm_list, num_comm_items);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_comm_destroy_list returned error %d\n", ret);
		goto error;
	}

	for (i = 0; i < 10; i++)
		rte_free(mbufs[i]);

	printf("\n=======> TEST: PASSED\n");
	return 0;

error:
	printf("\n=======> TEST: FAILED\n");
	return -1;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static int
rx_core(__rte_unused void *arg)
{
	uint32_t queue_id;
	uint32_t nb_rx = 0;
	int ret = 0;
	int comm_list_item = 0;
	struct rte_mbuf *rx_mbufs[RTE_GPU_COMM_LIST_PKTS_MAX];

	queue_id = (rte_lcore_index(rte_lcore_id()) - 1) / 2;

	printf("RX core started on queue %d.\n", queue_id);

	while (force_quit == false) {

		nb_rx = 0;
		while (nb_rx < RTE_GPU_COMM_LIST_PKTS_MAX &&
				nb_rx < (conf_burst - PKT_GAP) &&
				force_quit == false) {
			nb_rx += rte_eth_rx_burst(conf_port_id, queue_id,
										&(rx_mbufs[nb_rx]),
										(conf_burst - nb_rx));
		}

		ret = rte_gpu_comm_populate_list_pkts(
				&(comm_list_fwd[queue_id][comm_list_item]), rx_mbufs, nb_rx);
		if (ret) {
			fprintf(stderr,
					"rte_gpu_comm_populate_list_pkts error %d.\n", ret);
			return -1;
		}

#ifdef DEBUG_PRINT
		printf("RX %d pkts from item %d\n",
			comm_list_fwd[queue_id][comm_list_item].num_pkts,
			comm_list_item);
#endif

		WRITE_ONCE(comm_list_fwd[queue_id][comm_list_item].status, RTE_GPU_COMM_LIST_DONE);

		comm_list_item = (comm_list_item+1) % NUM_COMM_ITEMS;
	}

	return 0;
}

static int
tx_core(__rte_unused void *arg)
{
	uint32_t queue_id = 0;
	uint32_t nb_tx = 0;
	int ret = 0;
	int comm_list_item = 0;

	queue_id = (rte_lcore_index(rte_lcore_id()) - 1) / 2;
	printf("TX core started on queue %d.\n", queue_id);

	while (force_quit == false) {

#ifdef DEBUG_PRINT
		printf("Waiting on item %d\n", comm_list_item);
#endif
		while (ACCESS_ONCE(comm_list_fwd[queue_id][comm_list_item].status)
				!= RTE_GPU_COMM_LIST_DONE && force_quit == false);

		nb_tx = 0;
		while (nb_tx < comm_list_fwd[queue_id][comm_list_item].num_pkts) {
			nb_tx += rte_eth_tx_burst(conf_port_id, queue_id,
					&(comm_list_fwd[queue_id][comm_list_item].mbufs[nb_tx]),
					comm_list_fwd[queue_id][comm_list_item].num_pkts - nb_tx);
		}
		rte_wmb();

#ifdef DEBUG_PRINT
		printf("TX %d/%d pkts from item %d\n",
				nb_tx, comm_list_fwd[queue_id][comm_list_item].num_pkts,
				comm_list_item);
#endif
		ret = rte_gpu_comm_cleanup_list(&(comm_list_fwd[queue_id][comm_list_item]));
		if (ret) {
			fprintf(stderr, "rte_gpu_comm_cleanup_list error %d.\n", ret);
			return -1;
		}

		rte_mb();

		comm_list_item = (comm_list_item+1) % NUM_COMM_ITEMS;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int ret, core_id;
	int nb_gpus = 0;
	int nb_ports = 0;
	int16_t gpu_id = 0;
	uint32_t idx_q = 0;
	struct rte_gpu_info ginfo;
	struct rte_eth_dev_info dev_info;

	/* Init EAL. */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;
	if (argc > 1) {
		ret = args_parse(argc, argv);
		if (ret) {
			fprintf(stderr, "Input args error.\n");
			goto exit;
		}
	}

	argc -= ret;
	argv += ret;

	nb_gpus = rte_gpu_count_avail();
	printf("\n\nDPDK found %d GPUs:\n", nb_gpus);
	RTE_GPU_FOREACH(gpu_id)
	{
		if (rte_gpu_info_get(gpu_id, &ginfo))
			rte_exit(EXIT_FAILURE, "rte_gpu_info_get error - bye\n");

		printf("\tGPU ID %d\n\t\tparent ID %d GPU Bus ID %s NUMA node %d Tot memory %.02f MB, Tot processors %d\n",
				ginfo.dev_id,
				ginfo.parent,
				ginfo.name,
				ginfo.numa_node,
				(((float)ginfo.total_memory)/(float)1024)/(float)1024,
				ginfo.processor_count
			);
	}
	printf("\n\n");

	if (nb_gpus == 0) {
		fprintf(stderr, "Need at least one GPU on the system to run the example\n");
		goto exit;
	}

	if (nb_gpus < conf_gpu_id) {
		fprintf(stderr, "Not enough GPUs in the system (%d / %d).\n", nb_gpus, conf_gpu_id);
		goto exit;
	}

	if (conf_testapi == true) {
		/* Memory tests */
		alloc_gpu_memory(gpu_id);
		register_cpu_memory(gpu_id);

		/* Communication items test */
		create_update_comm_flag(gpu_id);
		create_update_comm_list(gpu_id);

		goto exit;
	}

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	ret = rte_eth_dev_info_get(conf_port_id, &dev_info);
	if (ret) {
		fprintf(stderr, "rte_eth_dev_info_get failed with %d.\n", ret);
		goto exit;
	}

	/* Create external memory mempool. */
	ext_mem.elt_size = conf_mbuf_dataroom + RTE_PKTMBUF_HEADROOM;
	ext_mem.buf_len = RTE_ALIGN_CEIL(conf_nb_mbuf * ext_mem.elt_size, GPU_PAGE_SIZE);

	if (conf_mtype == MEMORY_CPU) {
		ext_mem.buf_ptr = rte_malloc("extmem", ext_mem.buf_len, 0);
		if (ext_mem.buf_ptr == NULL) {
			fprintf(stderr, "Could not allocate CPU DPDK memory.\n");
			goto exit;
		}

		ret = rte_gpu_mem_register(conf_gpu_id, ext_mem.buf_len, ext_mem.buf_ptr);
		if (ret < 0) {
			fprintf(stderr,
					"rte_gpu_mem_register CPU memory returned error %d.\n", ret);
			return -1;
		}
	} else {
		ext_mem.buf_iova = RTE_BAD_IOVA;

		ext_mem.buf_ptr = rte_gpu_mem_alloc(conf_gpu_id, ext_mem.buf_len);
		if (ext_mem.buf_ptr == NULL) {
			fprintf(stderr, "Could not allocate GPU device memory.\n");
			goto exit;
		}

		ret = rte_extmem_register(ext_mem.buf_ptr, ext_mem.buf_len,
				NULL, ext_mem.buf_iova, GPU_PAGE_SIZE);
		if (ret) {
			fprintf(stderr, "Unable to register addr 0x%p, ret %d.\n", ext_mem.buf_ptr, ret);
			goto exit;
		}
	}

	/* DMA map the external memory. */
	ret = rte_dev_dma_map(dev_info.device, ext_mem.buf_ptr,
			ext_mem.buf_iova, ext_mem.buf_len);
	if (ret) {
		fprintf(stderr, "Could not DMA map EXT memory.\n");
		goto exit;
	}

	/* Create external memory mempool. */
	mpool = rte_pktmbuf_pool_create_extbuf("payload_mpool", conf_nb_mbuf,
			0, 0, ext_mem.elt_size,
			rte_socket_id(), &ext_mem, 1);
	if (mpool == NULL) {
		fprintf(stderr, "Could not create EXT memory mempool.\n");
		goto exit;
	}

	/* Queues configuration. */
	ret = rte_eth_dev_configure(conf_port_id, conf_queues,
			conf_queues, &port_conf);
	if (ret < 0) {
		fprintf(stderr,
				"Cannot configure device: err=%d, port=%u queues=%u\n",
				ret, conf_port_id, conf_queues);
		goto exit;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(conf_port_id,
			&conf_nb_descriptors, &conf_nb_descriptors);
	if (ret) {
		fprintf(stderr,
				"Cannot adjust number of descriptors: err=%d, port=%u\n",
				ret, conf_port_id);
		goto exit;
	}

	for (idx_q = 0; idx_q < conf_queues; idx_q++) {

		ret = rte_eth_rx_queue_setup(conf_port_id, idx_q,
				conf_nb_descriptors, rte_lcore_to_socket_id(idx_q),
				NULL, mpool);

		if (ret) {
			fprintf(stderr, "rte_eth_rx_queue_setup: err=%d, port=%u\n",
					ret, conf_port_id);
			goto exit;
		}

		ret = rte_eth_tx_queue_setup(conf_port_id, idx_q,
				conf_nb_descriptors, rte_lcore_to_socket_id(idx_q), NULL);
		if (ret) {
			fprintf(stderr, "rte_eth_tx_queue_setup: err=%d, port=%u\n",
					ret, conf_port_id);
			goto exit;
		}
	}

	rte_eth_macaddr_get(conf_port_id, &port_eth_addr);

	ret = rte_eth_dev_start(conf_port_id);
	if (ret) {
		fprintf(stderr, "rte_eth_dev_start: err=%d, port=%u\n",
				ret, conf_port_id);
			goto exit;
	}

	printf("Port %d: %02x:%02x:%02x:%02x:%02x:%02x started!\n",
				conf_port_id,
				(uint8_t)port_eth_addr.addr_bytes[0],
				(uint8_t)port_eth_addr.addr_bytes[1],
				port_eth_addr.addr_bytes[2],
				port_eth_addr.addr_bytes[3],
				port_eth_addr.addr_bytes[4],
				port_eth_addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(conf_port_id);

	/* Create communication lists, one per queue. */
	for (idx_q = 0; idx_q < MAX_QUEUES; idx_q++) {
		comm_list_fwd[idx_q] = NULL;

		if (idx_q < conf_queues) {
			comm_list_fwd[idx_q] = rte_gpu_comm_create_list(conf_gpu_id, NUM_COMM_ITEMS);
			if (comm_list_fwd[idx_q] == NULL) {
				fprintf(stderr, "rte_gpu_comm_create_list returned error %d\n", ret);
				goto exit;
			}
			ret = rte_gpu_comm_cleanup_list(&(comm_list_fwd[idx_q][0]));
			if (ret < 0) {
				fprintf(stderr, "rte_gpu_comm_cleanup_list returned error %d\n", ret);
				goto exit;
			}
		}
	}

	core_id = 0;
	for (idx_q = 0; idx_q < conf_queues; idx_q++) {
		core_id = rte_get_next_lcore(core_id, 1, 0);
		rte_eal_remote_launch(tx_core, NULL, core_id);

		core_id = rte_get_next_lcore(core_id, 1, 0);
		rte_eal_remote_launch(rx_core, NULL, core_id);
	}

	core_id = 0;
	RTE_LCORE_FOREACH_WORKER(core_id) {
		if (rte_eal_wait_lcore(core_id) < 0) {
			fprintf(stderr, "bad exit for core %d.\n",
					core_id);
			break;
		}
	}

	force_quit = true;

	ret = rte_dev_dma_unmap(dev_info.device, (void *)ext_mem.buf_ptr,
			RTE_BAD_IOVA, ext_mem.buf_len);
	if (ret) {
		fprintf(stderr,
				"rte_dev_dma_unmap 0x%p -> %d (rte_errno = %d)\n",
				(uint8_t *)ext_mem.buf_ptr, ret, rte_errno);
		goto exit;
	}

	if (conf_mtype == MEMORY_CPU) {
		ret = rte_gpu_mem_unregister(conf_gpu_id, ext_mem.buf_ptr);
		if (ret < 0) {
			fprintf(stderr, "rte_gpu_mem_unregister returned error %d\n", ret);
			goto exit;
		}

		rte_free(ext_mem.buf_ptr);

	} else {

		ret = rte_extmem_unregister(ext_mem.buf_ptr, ext_mem.buf_len);
		if (ret) {
			fprintf(stderr, "rte_extmem_unregister failed with %d.\n", ret);
			goto exit;
		}

		rte_gpu_mem_free(conf_gpu_id, (void *)ext_mem.buf_ptr);
	}

	rte_eth_dev_stop(conf_port_id);
	rte_eth_dev_close(conf_port_id);

exit:
	/* clean up the EAL */
	rte_eal_cleanup();

	printf("Bye...\n");
	return EXIT_SUCCESS;
}

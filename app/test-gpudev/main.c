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

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <rte_gpudev.h>

enum app_args {
	ARG_HELP,
	ARG_MEMPOOL
};

static void
usage(const char *prog_name)
{
	printf("%s [EAL options] --\n",
		prog_name);
}

static void
args_parse(int argc, char **argv)
{
	char **argvopt;
	int opt;
	int opt_idx;

	static struct option lgopts[] = {
		{ "help", 0, 0, ARG_HELP},
		/* End of options */
		{ 0, 0, 0, 0 }
	};

	argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case ARG_HELP:
			usage(argv[0]);
			break;
		default:
			usage(argv[0]);
			rte_exit(EXIT_FAILURE, "Invalid option: %s\n", argv[optind]);
			break;
		}
	}
}

static int
alloc_gpu_memory(uint16_t gpu_id)
{
	void *ptr_1 = NULL;
	void *ptr_2 = NULL;
	size_t buf_bytes = 1024;
	int ret;

	printf("\n=======> TEST: Allocate GPU memory\n");

	/* Alloc memory on GPU 0 */
	ptr_1 = rte_gpu_malloc(gpu_id, buf_bytes);
	if (ptr_1 == NULL) {
		fprintf(stderr, "rte_gpu_malloc GPU memory returned error\n");
		return -1;
	}
	printf("GPU memory allocated at 0x%p %zdB\n", ptr_1, buf_bytes);

	ptr_2 = rte_gpu_malloc(gpu_id, buf_bytes);
	if (ptr_2 == NULL) {
		fprintf(stderr, "rte_gpu_malloc GPU memory returned error\n");
		return -1;
	}
	printf("GPU memory allocated at 0x%p %zdB\n", ptr_2, buf_bytes);

	ret = rte_gpu_free(gpu_id, (uint8_t *)(ptr_1)+0x700);
	if (ret < 0) {
		printf("GPU memory 0x%p + 0x700 NOT freed because of memory address not recognized by driver\n", ptr_1);
	} else {
		fprintf(stderr, "rte_gpu_free erroneusly freed GPU memory 0x%p + 0x700\n", ptr_1);
		return -1;
	}

	ret = rte_gpu_free(gpu_id, ptr_2);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_free returned error %d\n", ret);
		return -1;
	}
	printf("GPU memory 0x%p freed\n", ptr_2);

	ret = rte_gpu_free(gpu_id, ptr_1);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_free returned error %d\n", ret);
		return -1;
	}
	printf("GPU memory 0x%p freed\n", ptr_1);

	return 0;
}

static int
register_cpu_memory(uint16_t gpu_id)
{
	void *ptr = NULL;
	size_t buf_bytes = 1024;
	int ret;

	printf("\n=======> TEST: Register CPU memory\n");

	/* Alloc memory on CPU visible from GPU 0 */
	ptr = rte_zmalloc(NULL, buf_bytes, 0);
	if (ptr == NULL) {
		fprintf(stderr, "Failed to allocate CPU memory.\n");
		return -1;
	}

	ret = rte_gpu_register(gpu_id, buf_bytes, ptr);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_register CPU memory returned error %d\n", ret);
		return -1;
	}
	printf("CPU memory registered at 0x%p %zdB\n", ptr, buf_bytes);

	ret = rte_gpu_unregister(gpu_id, (uint8_t *)(ptr)+0x700);
	if (ret < 0) {
		printf("CPU memory 0x%p + 0x700 NOT unregistered because of memory address not recognized by driver\n", ptr);
	} else {
		fprintf(stderr, "rte_gpu_free erroneusly freed GPU memory 0x%p + 0x700\n", ptr);
		return -1;
	}
	printf("CPU memory 0x%p unregistered\n", ptr);

	ret = rte_gpu_unregister(gpu_id, ptr);
	if (ret < 0) {
		fprintf(stderr, "rte_gpu_unregister returned error %d\n", ret);
		return -1;
	}
	printf("CPU memory 0x%p unregistered\n", ptr);

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	int nb_gpus = 0;
	int16_t gpu_id = 0;
	struct rte_gpu_info ginfo;

	/* Init EAL. */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;
	if (argc > 1)
		args_parse(argc, argv);
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
		return EXIT_FAILURE;
	}

	gpu_id = 0;

	/**
	 * Memory tests
	 */
	alloc_gpu_memory(gpu_id);
	register_cpu_memory(gpu_id);

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return EXIT_SUCCESS;
}

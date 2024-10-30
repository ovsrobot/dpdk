/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <getopt.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_log.h>

#define RTE_LOGTYPE_HELLOWORLD RTE_LOGTYPE_USER1
#define USE_NO_TOPOLOGY 0xffff

static uint16_t topo_sel = USE_NO_TOPOLOGY;
/* lcore selector based on Topology */
static const char short_options[] = "T:";

/* Launch a function on lcore. 8< */
static int
lcore_hello(__rte_unused void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();

	printf("hello from core %u\n", lcore_id);
	return 0;
}

static int
send_lcore_hello(__rte_unused void *arg)
{
	unsigned int lcore_id;
	uint16_t send_lcore_id;
	uint16_t send_count = 0;

	lcore_id = rte_lcore_id();

	send_lcore_id = rte_get_next_lcore_from_domain(lcore_id, false, true, topo_sel);

	while ((send_lcore_id != RTE_MAX_LCORE) && (lcore_id != send_lcore_id)) {
		printf("hello from core %u to core %u\n", lcore_id, send_lcore_id);
		send_lcore_id = rte_get_next_lcore_from_domain(send_lcore_id,
				false, true, topo_sel);
		send_count += 1;
	}

	if (send_count == 0)
		RTE_LOG(INFO, HELLOWORLD, "for lcoe %u; no lcores in same domain!!!\n", lcore_id);

	return 0;
}
/* >8 End of launching function on lcore. */

/* display usage. 8< */
static void
helloworld_usage(const char *prgname)
{
	printf("%s [EAL options] -- [-T TOPO]\n"
		"  -T TOPO: choose topology to send hello to\n"
		"	- 0: send cores sharing L1 (SMT)\n"
		"	- 1: send cores sharing L2\n"
		"	- 2: send cores sharing L3\n"
		"	- 3: send cores sharing IO\n\n",
		prgname);
}

static unsigned int
parse_topology(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse the topology option */
	n = strtoul(q_arg, &end, 10);

	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	if (n > 3)
		return USE_NO_TOPOLOGY;

	n = (n == 0) ? RTE_LCORE_DOMAIN_L1 :
		(n == 1) ? RTE_LCORE_DOMAIN_L2 :
		(n == 2) ? RTE_LCORE_DOMAIN_L3 :
		RTE_LCORE_DOMAIN_IO;

	return n;
}

/* Parse the argument given in the command line of the application */
static int
helloworld_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt = argv;
	int option_index;
	char *prgname = argv[0];
	while ((opt = getopt_long(argc, argvopt, short_options,
				NULL, &option_index)) != EOF) {
		switch (opt) {
		/* Topology selection */
		case 'T':
			topo_sel = parse_topology(optarg);
			if (topo_sel == USE_NO_TOPOLOGY) {
				helloworld_usage(prgname);
				rte_exit(EXIT_FAILURE, "Invalid Topology selection\n");
			}

			RTE_LOG(DEBUG, HELLOWORLD, "USR selects (%s) domain cores!\n",
				(topo_sel == RTE_LCORE_DOMAIN_L1) ? "L1" :
				(topo_sel == RTE_LCORE_DOMAIN_L2) ? "L2" :
				(topo_sel == RTE_LCORE_DOMAIN_L3) ? "L3" : "IO");
			ret = 0;
			break;
		default:
			helloworld_usage(prgname);
			return -1;
		}
	}
	if (optind >= 0)
		argv[optind-1] = prgname;
	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Initialization of Environment Abstraction Layer (EAL). 8< */
int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	/* >8 End of initialization of Environment Abstraction Layer */

	argc -= ret;
	argv += ret;

	ret = helloworld_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");

	if (topo_sel != USE_NO_TOPOLOGY) {
		uint16_t domain_count = rte_get_domain_count(topo_sel);
		RTE_LOG(DEBUG, HELLOWORLD, "selected Domain (%s)\n",
			(topo_sel == RTE_LCORE_DOMAIN_L1) ? "L1" :
			(topo_sel == RTE_LCORE_DOMAIN_L2) ? "L2" :
			(topo_sel == RTE_LCORE_DOMAIN_L3) ? "L3" : "IO");

		for (int i = 0; i < domain_count; i++) {
			uint16_t domain_lcore_count = rte_lcore_count_from_domain(topo_sel, i);
			uint16_t domain_lcore = rte_get_lcore_in_domain(topo_sel, i, 0);

			if (domain_lcore_count)
				RTE_LOG(DEBUG, HELLOWORLD, "at index (%u), %u cores, lcore (%u) at index 0\n",
					i,
					domain_lcore_count,
					domain_lcore);
		}
	}

	/* Launches the function on each lcore. 8< */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		/* Simpler equivalent. 8< */
		rte_eal_remote_launch((topo_sel == USE_NO_TOPOLOGY) ?
					lcore_hello : send_lcore_hello, NULL, lcore_id);
		/* >8 End of simpler equivalent. */
	}

	/* call it on main lcore too */
	if (topo_sel == USE_NO_TOPOLOGY)
		lcore_hello(NULL);
	else
		send_lcore_hello(NULL);

	/* >8 End of launching the function on each lcore. */

	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

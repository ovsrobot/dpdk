/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 *
 * This file contain the application main file
 * This application provides a way to test the RegEx class.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_regexdev.h>

#define HELP_VAL 0
#define RULES_VAL 1
#define DATA_VAL 2
#define JOB_VAL 3
#define PERF_VAL 4
#define ITER_VAL 5
#define MAX_FILE_NAME 255

static char rules_file[MAX_FILE_NAME];
static char data_file[MAX_FILE_NAME];
static uint32_t jobs;
static struct rte_mempool *mbuf_mp;
static uint8_t nb_max_matches;
static uint16_t nb_max_payload;
static int perf_test;
static uint32_t iter;

static void
usage(const char *prog_name)
{
	printf("%s [EAL options] --\n"
		" --rules NAME: precompiled rules file\n"
		" --data NAME: data file to use\n"
		" --nb_jobs: number of jobs to use\n"
		" --perf N: only outputs the performance data\n"
		" --nb_iter N: number of iteration to run\n",
		prog_name);
}

static void
args_parse(int argc, char **argv)
{
	char **argvopt;
	int opt;
	int opt_idx;
	size_t len;
	static struct option lgopts[] = {
		{ "help",  0, 0, HELP_VAL },
		{ "rules",  1, 0, RULES_VAL },
		/* Rules database file to load. */
		{ "data",  1, 0, DATA_VAL },
		/* Data file to load. */
		{ "nb_jobs",  1, 0, JOB_VAL },
		/* Number of jobs to create. */
		{ "perf", 0, 0, PERF_VAL},
		/* Perf test only */
		{ "nb_iter", 1, 0, ITER_VAL}
		/* Number of iterations to run with perf test */
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case RULES_VAL:
			len = strnlen(optarg, MAX_FILE_NAME - 1);
			if (len == MAX_FILE_NAME)
				rte_exit(EXIT_FAILURE,
					 "Rule file name to long max %d\n",
					 MAX_FILE_NAME - 1);
			strncpy(rules_file, optarg, MAX_FILE_NAME - 1);
			break;
		case DATA_VAL:
			len = strnlen(optarg, MAX_FILE_NAME - 1);
			if (len == MAX_FILE_NAME)
				rte_exit(EXIT_FAILURE,
					 "Data file name to long max %d\n",
					 MAX_FILE_NAME - 1);
			strncpy(data_file, optarg, MAX_FILE_NAME - 1);
			break;
		case JOB_VAL:
			jobs = atoi(optarg);
			break;
		case PERF_VAL:
			perf_test = 1;
			break;
		case ITER_VAL:
			iter = atoi(optarg);
			break;
		case HELP_VAL:
			usage("RegEx test app");
			break;
		default:
			fprintf(stderr, "Invalid option: %s\n", argv[optind]);
			usage("RegEx test app");
			rte_exit(EXIT_FAILURE, "Invalid option\n");
			break;
		}
	}

	if (!perf_test)
		iter = 1;
}

static long
read_file(char *file, char **buf)
{
	FILE *fp;
	long buf_len = 0;
	size_t read_len;
	int res = 0;

	fp = fopen(file, "r");
	if (!fp)
		return -EIO;
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len == -1) {
			res = EIO;
			goto error;
		}
		*buf = rte_malloc(NULL, sizeof(char) * (buf_len + 1), 4096);
		if (!*buf) {
			res = ENOMEM;
			goto error;
		}
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			res = EIO;
			goto error;
		}
		read_len = fread(*buf, sizeof(char), buf_len, fp);
		if (read_len != (unsigned long)buf_len) {
			res = EIO;
			goto error;
		}
	}
	fclose(fp);
	return buf_len;
error:
	printf("Error, can't open file %s\n, err = %d", file, res);
	if (fp)
		fclose(fp);
	if (*buf)
		rte_free(*buf);
	return -res;
}
#define MBUF_CACHE_SIZE 256
#define MBUF_SIZE (1 << 14)


static int
init_port(void)
{
	uint16_t id;
	uint16_t num_devs;
	char *rules = NULL;
	long rules_len;
	struct rte_regexdev_info info;
	struct rte_regexdev_config dev_conf = {
		.nb_queue_pairs = 1,
		.nb_groups = 1,
	};
	struct rte_regexdev_qp_conf qp_conf = {
		.nb_desc = 1024,
		.qp_conf_flags = RTE_REGEX_QUEUE_PAIR_CFG_OOS_F,
	};
	int res = 0;

	num_devs = rte_regexdev_count();
	if (num_devs == 0) {
		printf("Error, no devices detected.\n");
		return -EINVAL;
	}

	mbuf_mp = rte_pktmbuf_pool_create("mbuf_pool", jobs, 0,
					  0, MBUF_SIZE, rte_socket_id());
	if (mbuf_mp == NULL) {
		printf("Error, can't create memory pool\n");
		res = -ENOMEM;
		goto error;
	}

	rules_len = read_file(rules_file, &rules);
	if (rules_len < 0) {
		printf("Error, can't read rules files.\n");
		res = -EIO;
		goto error;
	}

	for (id = 0; id < num_devs; id++) {
		res = rte_regexdev_info_get(id, &info);
		if (res != 0) {
			printf("Error, can't get device info.\n");
			goto error;
		}
		printf(":: initializing dev: %d\n", id);
		nb_max_matches = info.max_matches;
		nb_max_payload = info.max_payload_size;
		if (info.regexdev_capa & RTE_REGEXDEV_SUPP_MATCH_AS_END_F)
			dev_conf.dev_cfg_flags |= RTE_REGEXDEV_CFG_MATCH_AS_END_F;
		dev_conf.nb_max_matches = info.max_matches;
		dev_conf.nb_rules_per_group = info.max_rules_per_group;
		dev_conf.rule_db_len = rules_len;
		dev_conf.rule_db = rules;
		res = rte_regexdev_configure(id, &dev_conf);
		if (res < 0) {
			printf("Error, can't configure device %d.\n", id);
			goto error;
		}
		res = rte_regexdev_queue_pair_setup(id, 0, &qp_conf);
		if (res < 0) {
			printf("Error, can't setup queue pair for device %d.\n",
			       id);
			goto error;
		}
		printf(":: initializing device: %d done\n", id);
	}
	rte_free(rules);
	return 0;
error:
	if (rules)
		rte_free(rules);
	if (mbuf_mp)
		rte_mempool_free(mbuf_mp);
	return res;

}

static void
extbuf_free_cb(void *addr __rte_unused, void *fcb_opaque __rte_unused)
{

}

#define START_BURST_SIZE 32u

static int
run_regex(void)
{
	char *buf;
	long buf_len;
	long job_len;
	uint32_t actual_jobs = 0;
	uint32_t i;
	struct rte_regex_ops **ops;
	uint16_t dev_id = 0;
	uint16_t qp_id = 0;
	uint8_t nb_matches;
	struct rte_regexdev_match *match;
	long pos = 0;
	unsigned long d_ind = 0;
	struct rte_mbuf_ext_shared_info shinfo;
	uint32_t total_enqueue = 0;
	uint32_t total_dequeue = 0;
	uint32_t total_matches = 0;
	int res = 0;
	time_t start;
	time_t end;
	double time;

	shinfo.free_cb = extbuf_free_cb;

	ops = rte_malloc(NULL, sizeof(*ops) * jobs, 0);
	if (!ops) {
		printf("Error, can't allocate memory for ops.\n");
		return -ENOMEM;
	}

	/* Allocate the jobs and assign each job with an mbuf. */
	for (i = 0; i < jobs; i++) {
		ops[i] = rte_malloc(NULL, sizeof(*ops[0]) + nb_max_matches *
				    sizeof(struct rte_regexdev_match), 0);
		if (!ops[i]) {
			printf("Error, can't allocate memory for op.\n");
			res = -ENOMEM;
			goto end;
		}
		ops[i]->mbuf = rte_pktmbuf_alloc(mbuf_mp);
		if (!ops[i]->mbuf) {
			printf("Error, can't attach mbuf.\n");
			res = -ENOMEM;
			goto end;
		}
	}

	buf_len = read_file(data_file, &buf);
	if (buf_len <= 0) {
		printf("Error, can't read file, or file is empty.\n");
		res = -EXIT_FAILURE;
		goto end;
	}

	job_len = buf_len / jobs;
	if (job_len == 0) {
		printf("Error, To many jobs, for the given input.\n");
		res = -EXIT_FAILURE;
		goto end;
	}

	if (job_len > nb_max_payload) {
		printf("Error, not enough jobs to cover input.\n");
		res = -EXIT_FAILURE;
		goto end;
	}

	/* Assign each mbuf with the data to handle. */
	for (i = 0; (pos < buf_len) && (i < jobs) ; i++) {
		long act_job_len = RTE_MIN(job_len, buf_len - pos);
		rte_pktmbuf_attach_extbuf(ops[i]->mbuf, &buf[pos], 0,
					  act_job_len, &shinfo);
		ops[i]->mbuf->data_len = job_len;
		ops[i]->mbuf->pkt_len = act_job_len;
		ops[i]->user_id = i;
		ops[i]->group_id0 = 1;
		pos += act_job_len;
		actual_jobs++;
	}

	start = clock();
	for (i = 0; i < iter; i++) {
		total_enqueue = 0;
		total_dequeue = 0;
		while (total_dequeue < actual_jobs) {
			struct rte_regex_ops **cur_ops_to_enqueue = ops +
				total_enqueue;
			struct rte_regex_ops **cur_ops_to_dequeue = ops +
				total_dequeue;

			if (actual_jobs - total_enqueue)
				total_enqueue += rte_regexdev_enqueue_burst
					(dev_id, qp_id, cur_ops_to_enqueue,
					 actual_jobs - total_enqueue);

			total_dequeue += rte_regexdev_dequeue_burst
				(dev_id, qp_id, cur_ops_to_dequeue,
				 total_enqueue - total_dequeue);
		}
	}
	end = clock();
	time = ((double)end - start) / CLOCKS_PER_SEC;
	printf("Job len = %ld Bytes\n",  job_len);
	printf("Time = %lf sec\n",  time);
	printf("Perf = %lf Gbps\n",
	       (((double)buf_len * iter * 8) / time)/1000000000.0);

	if (!perf_test) {
		/* Log results per job. */
		for (d_ind = 0; d_ind < total_dequeue; d_ind++) {
			nb_matches = ops[d_ind % actual_jobs]->nb_matches;
			printf("Job id %ld number of matches = %d\n",
			       ops[d_ind]->user_id, nb_matches);
			total_matches += nb_matches;
			match = ops[d_ind % actual_jobs]->matches;
			for (i = 0; i < nb_matches; i++) {
				printf("match %d, rule = %d, start = %d,len = %d\n",
				       i, match->rule_id, match->start_offset,
				       match->len);
				match++;
			}
		}
		printf("Total matches = %d\n", total_matches);
		printf("All Matches:\n");

		/* Log absolute results. */
		for (d_ind = 0; d_ind < total_dequeue; d_ind++) {
			nb_matches = ops[d_ind % actual_jobs]->nb_matches;
			total_matches += nb_matches;
			match = ops[d_ind % actual_jobs]->matches;
			for (i = 0; i < nb_matches; i++) {
				printf("start = %ld, len = %d, rule = %d\n",
				       match->start_offset + d_ind * job_len,
				       match->len, match->rule_id);
				match++;
			}
		}
	}
end:
	for (i = 0; i < actual_jobs; i++) {
		if (ops[i]) {
			if (ops[i]->mbuf)
				rte_pktmbuf_free(ops[i]->mbuf);
			rte_free(ops[i]);
		}
	}
	rte_free(ops);
	rte_free(buf);
	return res;
}

int
main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;
	if (argc > 1)
		args_parse(argc, argv);

	ret = init_port();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init port failed\n");
	ret = run_regex();
	if (ret < 0) {
		rte_mempool_free(mbuf_mp);
		rte_exit(EXIT_FAILURE, "RegEx function failed\n");
	}
	rte_mempool_free(mbuf_mp);
	return 0;
}

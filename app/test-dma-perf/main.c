/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <libgen.h>

#include <rte_eal.h>
#include <rte_cfgfile.h>
#include <rte_string_fns.h>
#include <rte_lcore.h>

#include "main.h"

#define CSV_HDR_FMT "Case %u : %s,lcore,DMA,buffer size,nr_buf,memory(MB),cycle,bandwidth(Gbps),MOps\n"

#define MAX_EAL_PARAM_NB 100
#define MAX_EAL_PARAM_LEN 1024

#define DMA_MEM_COPY "DMA_MEM_COPY"
#define CPU_MEM_COPY "CPU_MEM_COPY"

#define CMDLINE_CONFIG_ARG "--config"
#define CMDLINE_RESULT_ARG "--result"

#define MAX_PARAMS_PER_ENTRY 4

#define MAX_LONG_OPT_SZ 64

enum {
	TEST_TYPE_NONE = 0,
	TEST_TYPE_DMA_MEM_COPY,
	TEST_TYPE_CPU_MEM_COPY
};

#define MAX_TEST_CASES 16
static struct test_configure test_cases[MAX_TEST_CASES];

char output_str[MAX_WORKER_NB][MAX_OUTPUT_STR_LEN];

static FILE *fd;

static void
output_csv(bool need_blankline)
{
	uint32_t i;

	if (need_blankline) {
		fprintf(fd, ",,,,,,,,\n");
		fprintf(fd, ",,,,,,,,\n");
	}

	for (i = 0; i < RTE_DIM(output_str); i++) {
		if (output_str[i][0]) {
			fprintf(fd, "%s", output_str[i]);
			output_str[i][0] = '\0';
		}
	}

	fflush(fd);
}

static void
output_env_info(void)
{
	snprintf(output_str[0], MAX_OUTPUT_STR_LEN, "test environment:\n");
	snprintf(output_str[1], MAX_OUTPUT_STR_LEN, "frequency,%" PRIu64 "\n", rte_get_timer_hz());

	output_csv(true);
}

static void
output_header(uint32_t case_id, struct test_configure *case_cfg)
{
	snprintf(output_str[0], MAX_OUTPUT_STR_LEN,
			CSV_HDR_FMT, case_id, case_cfg->test_type_str);

	output_csv(true);
}

static void
run_test_case(struct test_configure *case_cfg)
{
	switch (case_cfg->test_type) {
	case TEST_TYPE_DMA_MEM_COPY:
		mem_copy_benchmark(case_cfg, true);
		break;
	case TEST_TYPE_CPU_MEM_COPY:
		mem_copy_benchmark(case_cfg, false);
		break;
	default:
		printf("Unknown test type. %s\n", case_cfg->test_type_str);
		break;
	}
}

static void
run_test(uint32_t case_id, struct test_configure *case_cfg)
{
	uint32_t i;
	uint32_t nb_lcores = rte_lcore_count();
	struct test_configure_entry *mem_size = &case_cfg->mem_size;
	struct test_configure_entry *buf_size = &case_cfg->buf_size;
	struct test_configure_entry *ring_size = &case_cfg->ring_size;
	struct test_configure_entry *kick_batch = &case_cfg->kick_batch;
	struct test_configure_entry dummy = { 0 };
	struct test_configure_entry *var_entry = &dummy;



	for (i = 0; i < RTE_DIM(output_str); i++)
		memset(output_str[i], 0, MAX_OUTPUT_STR_LEN);

	if (nb_lcores <= case_cfg->nb_workers) {
		printf("Case %u: Not enough lcores (%u) for all workers (%u).\n",
			case_id, nb_lcores, case_cfg->nb_workers);
		return;
	}

	printf("Number of used lcores: %u.\n", nb_lcores);

	if (mem_size->incr != 0)
		var_entry = mem_size;

	if (buf_size->incr != 0)
		var_entry = buf_size;

	if (ring_size->incr != 0)
		var_entry = ring_size;

	if (kick_batch->incr != 0)
		var_entry = kick_batch;

	case_cfg->scenario_id = 0;

	output_header(case_id, case_cfg);

	for (var_entry->cur = var_entry->first; var_entry->cur <= var_entry->last;) {
		case_cfg->scenario_id++;
		printf("\nRunning scenario %d\n", case_cfg->scenario_id);

		run_test_case(case_cfg);
		output_csv(false);

		if (var_entry->op == OP_MUL)
			var_entry->cur *= var_entry->incr;
		else if (var_entry->op == OP_ADD)
			var_entry->cur += var_entry->incr;
		else
			break;
	}

}

static int
parse_entry(const char *value, struct test_configure_entry *entry)
{
	char input[255] = {0};
	char *args[MAX_PARAMS_PER_ENTRY];
	int args_nr = -1;

	strncpy(input, value, 254);
	if (*input == '\0')
		goto out;

	args_nr = rte_strsplit(input, strlen(input), args, MAX_PARAMS_PER_ENTRY, ',');
	if (args_nr <= 0)
		goto out;

	entry->cur = entry->first = (uint32_t)atoi(args[0]);
	entry->last = args_nr > 1 ? (uint32_t)atoi(args[1]) : 0;
	entry->incr = args_nr > 2 ? (uint32_t)atoi(args[2]) : 0;

	if (args_nr > 3) {
		if (!strcmp(args[3], "MUL"))
			entry->op = OP_MUL;
		else if (!strcmp(args[3], "ADD"))
			entry->op = OP_ADD;
		else {
			printf("Invalid op %s", args[3]);
			args_nr = -1;
		}
	} else
		entry->op = OP_NONE;
out:
	return args_nr;
}

static void
load_configs(const char *path)
{
	struct rte_cfgfile *cfgfile;
	int nb_sections, i;
	struct test_configure *test_case;
	char section_name[CFG_NAME_LEN];
	const char *case_type;
	const char *mem_size_str, *buf_size_str, *ring_size_str, *kick_batch_str;
	int args_nr, nb_vp;
	bool is_dma;

	cfgfile = rte_cfgfile_load(path, 0);
	if (!cfgfile) {
		printf("Open configure file error.\n");
		exit(1);
	}

	nb_sections = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	if (nb_sections > MAX_TEST_CASES) {
		printf("Error: The maximum number of cases is %d.\n", MAX_TEST_CASES);
		exit(1);
	}

	for (i = 0; i < nb_sections; i++) {
		snprintf(section_name, CFG_NAME_LEN, "case%d", i + 1);
		test_case = &test_cases[i];
		case_type = rte_cfgfile_get_entry(cfgfile, section_name, "type");
		if (!case_type) {
			printf("Error: No case type in case %d\n.", i + 1);
			exit(1);
		}

		if (strcmp(case_type, DMA_MEM_COPY) == 0) {
			test_case->test_type = TEST_TYPE_DMA_MEM_COPY;
			test_case->test_type_str = DMA_MEM_COPY;
			is_dma = true;
		} else if (strcmp(case_type, CPU_MEM_COPY) == 0) {
			test_case->test_type = TEST_TYPE_CPU_MEM_COPY;
			test_case->test_type_str = CPU_MEM_COPY;
			is_dma = false;
		} else {
			printf("Error: Cannot find case type %s.\n", case_type);
			exit(1);
		}

		nb_vp = 0;

		test_case->src_numa_node = (int)atoi(rte_cfgfile_get_entry(cfgfile,
								section_name, "src_numa_node"));
		test_case->dst_numa_node = (int)atoi(rte_cfgfile_get_entry(cfgfile,
								section_name, "dst_numa_node"));

		mem_size_str = rte_cfgfile_get_entry(cfgfile, section_name, "mem_size");
		args_nr = parse_entry(mem_size_str, &test_case->mem_size);
		if (args_nr < 0) {
			printf("parse error\n");
			break;
		} else if (args_nr > 1)
			nb_vp++;

		buf_size_str = rte_cfgfile_get_entry(cfgfile, section_name, "buf_size");
		args_nr = parse_entry(buf_size_str, &test_case->buf_size);
		if (args_nr < 0) {
			printf("parse error\n");
			break;
		} else if (args_nr > 1)
			nb_vp++;

		if (is_dma) {
			ring_size_str = rte_cfgfile_get_entry(cfgfile, section_name,
								"dma_ring_size");
			args_nr = parse_entry(ring_size_str, &test_case->ring_size);
			if (args_nr < 0) {
				printf("parse error\n");
				break;
			} else if (args_nr > 1)
				nb_vp++;

			kick_batch_str = rte_cfgfile_get_entry(cfgfile, section_name, "kick_batch");
			args_nr = parse_entry(kick_batch_str, &test_case->kick_batch);
			if (args_nr < 0) {
				printf("parse error\n");
				break;
			} else if (args_nr > 1)
				nb_vp++;
		}

		if (nb_vp > 1) {
			printf("Error, each section can only have a single variable parameter.\n");
			break;
		}

		test_case->cache_flush =
			(int)atoi(rte_cfgfile_get_entry(cfgfile, section_name, "cache_flush"));
		test_case->test_secs = (uint16_t)atoi(rte_cfgfile_get_entry(cfgfile,
					section_name, "test_seconds"));
		test_case->nb_workers = (uint16_t)atoi(rte_cfgfile_get_entry(cfgfile,
					section_name, "worker_threads"));

		test_case->eal_args = rte_cfgfile_get_entry(cfgfile, section_name, "eal_args");
	}

	rte_cfgfile_close(cfgfile);
}

/* Parse the argument given in the command line of the application */
static int
append_eal_args(int argc, char **argv, const char *eal_args, char **new_argv)
{
	int i;
	char *tokens[MAX_EAL_PARAM_NB];
	char args[MAX_EAL_PARAM_LEN] = {0};
	int token_nb, new_argc = 0;

	for (i = 0; i < argc; i++) {
		if ((strcmp(argv[i], CMDLINE_CONFIG_ARG) == 0) ||
				(strcmp(argv[i], CMDLINE_RESULT_ARG) == 0)) {
			i++;	// skip the value argument
			continue;
		}
		strlcpy(new_argv[new_argc], argv[i], sizeof(new_argv[new_argc]));
		new_argc++;
	}

	if (eal_args) {
		strlcpy(args, eal_args, sizeof(args));
		token_nb = rte_strsplit(args, strlen(args),
					tokens, MAX_EAL_PARAM_NB, ' ');
		for (i = 0; i < token_nb; i++)
			strcpy(new_argv[new_argc++], tokens[i]);
	}

	return new_argc;
}

int
main(int argc, char *argv[])
{
	int ret;
	uint32_t i, nb_lcores;
	pid_t cpid, wpid;
	int wstatus;
	char args[MAX_EAL_PARAM_NB][MAX_EAL_PARAM_LEN];
	char *pargs[MAX_EAL_PARAM_NB];
	char *cfg_path_ptr = NULL;
	char *rst_path_ptr = NULL;
	char rst_path[PATH_MAX];
	int new_argc;
	bool is_first_case = true;

	memset(args, 0, sizeof(args));

	for (i = 0; i < RTE_DIM(pargs); i++)
		pargs[i] = args[i];

	for (i = 0; i < (uint32_t)argc; i++) {
		if (strncmp(argv[i], CMDLINE_CONFIG_ARG, MAX_LONG_OPT_SZ) == 0)
			cfg_path_ptr = argv[i + 1];
		if (strncmp(argv[i], CMDLINE_RESULT_ARG, MAX_LONG_OPT_SZ) == 0)
			rst_path_ptr = argv[i + 1];
	}
	if (cfg_path_ptr == NULL) {
		printf("Config file not assigned.\n");
		return -1;
	}
	if (rst_path_ptr == NULL) {
		// if the result output file is not configured, let it base on the config file name.
		strlcpy(rst_path, cfg_path_ptr, PATH_MAX);
		strcat(strtok(basename(rst_path), "."), "_result.csv");
		rst_path_ptr = rst_path;
	}

	load_configs(cfg_path_ptr);
	fd = fopen(rst_path_ptr, "w");
	if (fd == NULL) {
		printf("Open output CSV file error.\n");
		return -1;
	}
	fclose(fd);

	for (i = 0; i < MAX_TEST_CASES; i++) {
		if (test_cases[i].test_type == TEST_TYPE_NONE)
			continue;

		cpid = fork();
		if (cpid < 0) {
			printf("Fork case %d failed.\n", i + 1);
			exit(EXIT_FAILURE);
		} else if (cpid == 0) {
			printf("\nRunning case %u\n", i + 1);

			new_argc = append_eal_args(argc, argv, test_cases[i].eal_args, pargs);
			ret = rte_eal_init(new_argc, pargs);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

			/* Check lcores. */
			nb_lcores = rte_lcore_count();
			if (nb_lcores < 2)
				rte_exit(EXIT_FAILURE,
					"There should be at least 2 worker lcores.\n");

			fd = fopen(rst_path_ptr, "a");
			if (!fd) {
				printf("Open output CSV file error.\n");
				return 0;
			}

			if (is_first_case) {
				output_env_info();
				is_first_case = false;
			}
			run_test(i + 1, &test_cases[i]);

			/* clean up the EAL */
			rte_eal_cleanup();

			fclose(fd);

			printf("\nCase %u completed.\n", i + 1);

			exit(EXIT_SUCCESS);
		} else {
			wpid = waitpid(cpid, &wstatus, 0);
			if (wpid == -1) {
				printf("waitpid error.\n");
				exit(EXIT_FAILURE);
			}

			if (WIFEXITED(wstatus))
				printf("Case process exited. status %d\n",
					WEXITSTATUS(wstatus));
			else if (WIFSIGNALED(wstatus))
				printf("Case process killed by signal %d\n",
					WTERMSIG(wstatus));
			else if (WIFSTOPPED(wstatus))
				printf("Case process stopped by signal %d\n",
					WSTOPSIG(wstatus));
			else if (WIFCONTINUED(wstatus))
				printf("Case process continued.\n");
			else
				printf("Case process unknown terminated.\n");
		}
	}

	printf("Bye...\n");
	return 0;
}


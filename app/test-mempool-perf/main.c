/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_argparse.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_string_fns.h>

#define DEFAULT_CACHE_SIZE          512
#define DEFAULT_RAND_FACTOR         8
#define DEFAULT_BURST_SIZE          32
#define DEFAULT_NB_BUFS_PER_LCORE   1024

struct test_config {
	char     mempool_type[RTE_MEMPOOL_NAMESIZE];
	uint32_t nb_bufs;
	uint32_t cache_size;
	uint32_t nb_threads;
	uint32_t rand_factor;
	uint32_t burst_size;
	bool     access_on_alloc;
};

static struct test_config cfg = {
	.mempool_type   = "",
	.nb_bufs        = 0,  /* 0 means: compute from lcore count */
	.cache_size     = DEFAULT_CACHE_SIZE,
	.nb_threads     = 0,  /* 0 means: use all worker lcores */
	.rand_factor    = DEFAULT_RAND_FACTOR,
	.burst_size     = DEFAULT_BURST_SIZE,
	.access_on_alloc = true,
};

static void
apply_defaults(void)
{
	unsigned int nb_workers;

	nb_workers = rte_lcore_count() > 1 ? rte_lcore_count() - 1 : 1;

	if (cfg.nb_bufs == 0)
		cfg.nb_bufs = DEFAULT_NB_BUFS_PER_LCORE * rte_lcore_count();
	if (cfg.nb_threads == 0)
		cfg.nb_threads = nb_workers;
}

static bool
is_valid_mempool_type(const char *name)
{
	uint32_t i;

	for (i = 0; i < rte_mempool_ops_table.num_ops; i++)
		if (strcmp(name, rte_mempool_ops_table.ops[i].name) == 0)
			return true;
	return false;
}

static void
list_mempool_types(void)
{
	uint32_t i;

	printf("Available mempool types:\n");
	for (i = 0; i < rte_mempool_ops_table.num_ops; i++)
		printf("  [%u] %s\n", i, rte_mempool_ops_table.ops[i].name);
}

static void
print_config(void)
{
	printf("\n=== test-mempool-perf configuration ===\n");
	printf("  Mempool type     : %s\n", cfg.mempool_type);
	printf("  Num buffers      : %" PRIu32 "\n", cfg.nb_bufs);
	printf("  Cache size       : %" PRIu32 "\n", cfg.cache_size);
	printf("  Thread count     : %" PRIu32 "\n", cfg.nb_threads);
	printf("  Randomness factor: %" PRIu32 "\n", cfg.rand_factor);
	printf("  Burst size       : %" PRIu32 "\n", cfg.burst_size);
	printf("  Access on alloc  : %s\n", cfg.access_on_alloc ? "yes" : "no");
	printf("========================================\n\n");
}

static void
print_reproduce_cmd(void)
{
	printf("Reproduce using parameters:"
		" -M %s -n %" PRIu32 " -c %" PRIu32 " -t %" PRIu32 " -r %" PRIu32 " -b %" PRIu32 " %s\n\n",
			cfg.mempool_type, cfg.nb_bufs, cfg.cache_size, cfg.nb_threads, cfg.rand_factor,
			cfg.burst_size, cfg.access_on_alloc ? "-A" : "-N");
}

static void
trim_newline(char *s)
{
	size_t len = strlen(s);

	if (len > 0 && s[len - 1] == '\n')
		s[len - 1] = '\0';
}

static int
prompt_uint32(const char *prompt, uint32_t *val)
{
	char buf[64];
	char *end;
	unsigned long v;

	fputs(prompt, stdout);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL)
		return -1;
	trim_newline(buf);
	if (buf[0] == '\0')
		return 0;  /* keep default */

	v = strtoul(buf, &end, 0);
	if (*end != '\0') {
		fprintf(stderr, "Invalid number: %s\n", buf);
		return -1;
	}
	*val = (uint32_t)v;
	return 1;
}

static int
run_interactive_mode(void)
{
	char prompt[128];
	char buf[RTE_MEMPOOL_NAMESIZE];

	printf("\n=== test-mempool-perf interactive setup ===\n");
	printf("Press Enter to accept the default value.\n\n");

	list_mempool_types();
	printf("\n");

	/* Mempool type is required; loop until a valid name is entered */
	for (;;) {
		printf("Mempool type (required): ");
		fflush(stdout);
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			return -1;
		trim_newline(buf);
		if (buf[0] == '\0') {
			printf("  A mempool type is required; please enter one of the names above.\n");
			continue;
		}
		if (is_valid_mempool_type(buf))
			break;
		printf("  Unknown mempool type '%s'; please enter one of the names above.\n", buf);
	}
	rte_strscpy(cfg.mempool_type, buf, sizeof(cfg.mempool_type));

	/* Compute numeric defaults now that EAL is initialised */
	apply_defaults();

	/* Number of buffers */
	snprintf(prompt, sizeof(prompt),
		 "Number of buffers [%" PRIu32 "]: ", cfg.nb_bufs);
	if (prompt_uint32(prompt, &cfg.nb_bufs) < 0)
		return -1;

	/* Cache size */
	snprintf(prompt, sizeof(prompt),
		 "Cache size [%" PRIu32 "]: ", cfg.cache_size);
	if (prompt_uint32(prompt, &cfg.cache_size) < 0)
		return -1;

	/* Thread count */
	snprintf(prompt, sizeof(prompt),
		 "Thread count [%" PRIu32 "]: ", cfg.nb_threads);
	if (prompt_uint32(prompt, &cfg.nb_threads) < 0)
		return -1;

	/* Randomness factor */
	snprintf(prompt, sizeof(prompt),
		 "Randomness factor [%" PRIu32 "]: ", cfg.rand_factor);
	if (prompt_uint32(prompt, &cfg.rand_factor) < 0)
		return -1;

	/* Burst size */
	snprintf(prompt, sizeof(prompt),
		 "Burst size [%" PRIu32 "]: ", cfg.burst_size);
	if (prompt_uint32(prompt, &cfg.burst_size) < 0)
		return -1;
	/* Access on allocation */
	printf("Access buffers on allocation [%s]: ",
	       cfg.access_on_alloc ? "yes" : "no");
	fflush(stdout);
	{
		char yn[16];

		if (fgets(yn, sizeof(yn), stdin) == NULL)
			return -1;
		trim_newline(yn);
		if (yn[0] == 'y' || yn[0] == 'Y')
			cfg.access_on_alloc = true;
		else if (yn[0] == 'n' || yn[0] == 'N')
			cfg.access_on_alloc = false;
		/* else keep default */
	}

	return 0;
}

static bool summary_only;

/* Used only in non-interactive mode to receive the --mempool-type string */
static const char *mempool_type_arg;

static int
parse_args(int argc, char **argv)
{
	static struct rte_argparse obj = {
		.prog_name = "test-mempool-perf",
		.usage = "[EAL options] -- [options]",
		.descriptor = "Mempool performance tester",
		.exit_on_error = true,
		.args = {
			{ "--mempool-type", "-M",
			  "Mempool driver to test (required in non-interactive mode)",
			  (void *)&mempool_type_arg, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_STR,
			},
			{ "--nb-bufs", "-n",
			  "Number of buffers in the pool (default: 1024 * lcore count)",
			  (void *)&cfg.nb_bufs, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--cache-size", "-c",
			  "Per-lcore object cache size (default: 512)",
			  (void *)&cfg.cache_size, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--nb-threads", "-t",
			  "Number of worker threads to use (default: all worker lcores)",
			  (void *)&cfg.nb_threads, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--rand-factor", "-r",
			  "Randomness factor for alloc/free burst sizes (default: 8)",
			  (void *)&cfg.rand_factor, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--burst-size", "-b",
			  "Number of objects per alloc/free burst (default: 32)",
			  (void *)&cfg.burst_size, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--access-on-alloc", "-A",
			  "Enable touching buffer memory on allocation (default: enabled)",
			  (void *)&cfg.access_on_alloc, (void *)true,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			{ "--no-access-on-alloc", "-N",
			  "Disable touching buffer memory on allocation",
			  (void *)&cfg.access_on_alloc, (void *)false,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			{ "--summary", "-s",
			  "Print only the aggregate total, not per-lcore results",
			  (void *)&summary_only, (void *)true,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			ARGPARSE_ARG_END(),
		},
	};
	int ret;

	ret = rte_argparse_parse(&obj, argc, argv);
	if (ret < 0)
		return ret;

	if (mempool_type_arg != NULL)
		rte_strscpy(cfg.mempool_type, mempool_type_arg,
			    sizeof(cfg.mempool_type));

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	if (argc == 1) {
		/* No app-specific arguments: enter interactive configuration */
		ret = run_interactive_mode();
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Interactive configuration failed\n");
		print_reproduce_cmd();
	} else {
		ret = parse_args(argc, argv);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Invalid application arguments\n");

		if (cfg.mempool_type[0] == '\0') {
			fprintf(stderr,
				"Error: --mempool-type is required in non-interactive mode\n");
			list_mempool_types();
			rte_exit(EXIT_FAILURE, "Mempool type not specified\n");
		}
		if (!is_valid_mempool_type(cfg.mempool_type)) {
			fprintf(stderr, "Error: unknown mempool type '%s'\n",
				cfg.mempool_type);
			list_mempool_types();
			rte_exit(EXIT_FAILURE, "Invalid mempool type\n");
		}

		apply_defaults();
	}

	print_config();

	rte_eal_cleanup();
	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

#include <rte_string_fns.h>
#include <rte_comp.h>

#include "mp_crypto_parser.h"
#include "mp_crypto.h"

struct mp_crypto_app_parameters *mp_app_params;

static void
usage(char *progname)
{
	/* TODO, find better way of formatting columns... */
	printf("%s [EAL options] -- [options]"
			"\noptions:"
			" \n  --devtype [device name]: \t\t\tdevice name, the same name need to be used"
			" across all processes. \n\t\t\t\t\t\t--Example: --devtype=crypto_qat"
			" \n  --config-dev [dev_id,]: \t\t\tid of device that should be"
			" configured by this process. Note that order of ids depends on the"
			" Cryptodev\n\t\t\t\t\t\tglobal array placement so BDF of smaller numbers will come"
			" first. \n\t\t\t\t\t\t--Example: -w 03:01.2 -w 03:01.1 -w 03:01.3 --config-dev 0,2"
			" will configure devices 03:01.1 and 03:01.3."
			"\n  --qp-config=[dev_id]:[qp_id,];...: \t\tqueue_pairs qp_id's to be configured dev_id's"
			"\n\t\t\t\t\t\t--Example: --qp-config=0:0,1;1:1;0:1; - will configure qp's 0,1 on device 0"
			"' 1 on device 1, 0,1 on device 2.'"
			"\n  --session-mask=[mask]\t\t\t\tsession to be shared for all processes, session list is in"
			" mp_crypto_vectors.c file.\n\t\t\t\t\t\tIf session mask will not be set it still can be configured"
			" interactively by user for certain process and the used by this process only"
			"\n\t\t\t\t\t\t--Example --sesion-mask=0x3 will configure session 0 and 1."
			"\n  --enq=[dev_id]:[qp_id]:[ops]:[vector_id]:\tEnqueue operation for this process"
			"\n\t\t\t\t\t\t- dev_id: device selected the same way as in --config-dev option"
			"\n\t\t\t\t\t\t- qp_id: queue pair to bu used for enqueue operation"
			"\n\t\t\t\t\t\t- ops: 0 means it will run in infinite loop (ctrl-c will inform other processes),"
			"other than that any positive number"
			"\n\t\t\t\t\t\t- vector_id: vector id to be used, vector array can be found"
			" in mp_crypto_vectors.c file. "
			"\n\t\t\t\t\t\t- Only one can be specified by process"
			"\n  --deq=[dev_id]:[qp_id]:[ops]:[vector_id]:\tDequeue operation for this process"
			"\n\t\t\t\t\t\t- dev_id: device selected the same way as in --config-dev option"
			"\n\t\t\t\t\t\t- qp_id: queue pair to bu used for dequeue operation"
			"\n\t\t\t\t\t\t- ops: 0 means it will run in infinite loop (ctrl-c will inform other processes),"
			"other than that any positive number"
			"\n\t\t\t\t\t\t- vector_id: vector id to be used, vector array can be found"
			" in mp_crypto_vectors.c file. "
			"\n\t\t\t\t\t\t- Only one can be specified by process"
			"\n  --print-stats: \t\t\t\tPrint stats at then end of program."
			"\n",
		progname);
	return;
}

static struct option lgopts[] = {
	{ MP_DEV_CONFIGURE, required_argument, 0, 0 },
	{ MP_QP_CONFIGURE, required_argument, 0, 0 },
	{ MP_ENQ, required_argument, 0, 0 },
	{ MP_DEQ, required_argument, 0, 0 },
	{ MP_SESSION_MASK, required_argument, 0, 0 },
	{ MP_PRINT_STATS, 0, 0, 0 },
	{ MP_DEVTYPE_NAME, required_argument, 0, 0 },
	{ NULL, 0, 0, 0 }
};

static void dump_test_data_options(struct mp_crypto_app_parameters
	*test_data __rte_unused) {
	return;
}

int16_t
get_options(int argc, char *argv[]) {
	mp_app_params = rte_zmalloc_socket(NULL,
					sizeof(struct mp_crypto_app_parameters),
					0, rte_socket_id());

	if (mp_app_params == NULL) {
		RTE_LOG(ERR, USER1,
			"Failed to allocate for test data\n");
	}

	options_default(mp_app_params);

	if (options_parse(mp_app_params, argc, argv) != 0) {
		MP_APP_LOG_2(ERR, COL_RED,
			"Parsing one or more user options failed");
		return -1;
	}

	if (options_check(mp_app_params) != 0) {
		RTE_LOG(ERR, USER1,
			"Inconsistent user options.\n");
		dump_test_data_options(mp_app_params);
		return -1;
	}

	dump_test_data_options(mp_app_params);
	return 0;
}

static int
parse_config_dev(struct mp_crypto_app_parameters *mp_params,
					const char *arg)
{
	char *end = NULL;
	const char *start = arg;
	uint64_t num;
	char str[32];

	while (1) {
		memset(str, 0, sizeof(str));
		end = strchr(start, ',');
		if (end) {
			memcpy(str, start, end - start);
			errno = 0;
			num = strtoull(str, NULL, 10);
			if (errno) {
				MP_APP_LOG(ERR, COL_RED,
				"Invalid device provided '%s'", str);
				return -1;
			}
			if (num >= 64) {
				MP_APP_LOG(ERR, COL_RED,
				"Device number not supported %lu", num);
				return -1;
			}
			/* Sanity check, unfortunately c standard does not force errno to be set
			 * when no conversion can by performed (except for ERANGE)
			 */
			if (num == 0) {
				if (start[0] != '0') {
					MP_APP_LOG(ERR, COL_RED,
					"Invalid device provided '%s'", str);
					return -1;
				}
				if (start[1] != ',') {
					MP_APP_LOG(ERR, COL_RED,
					"Invalid device provided '%s'", str);
					return -1;
				}
			}
			mp_params->dev_to_configure_mask |= 1LU << (num);
			start = end + 1;
			if (*start == 0)
				break;
		} else {
			end = strchr(start, '\0');
			memcpy(str, start, end - start);
			errno = 0;
			num = strtoull(str, NULL, 10);
			if (errno) {
				MP_APP_LOG(ERR, COL_RED,
				"Invalid device provided '%s'", str);
				return -1;
			}
			if (num >= 64) {
				MP_APP_LOG(ERR, COL_RED,
				"Device number not supported %lu", num);
				return -1;
			}
			/* Sanity check, unfortunately c standard does not force
			 * errno to be set when no conversion can by performed
			 * (except for ERANGE)
			 */
			if (num == 0) {
				if (start[0] != '0') {
					MP_APP_LOG(ERR, COL_RED,
					"Invalid device provided '%s'", str);
					return -1;
				}
				if (start[1] != '\0') {
					MP_APP_LOG(ERR, COL_RED,
					"Invalid device provided '%s'", str);
					return -1;
				}
			}
			mp_params->dev_to_configure_mask |= 1LU << (num);
			break;
		}
	}

	return 0;
}

/* Veeeery simple parser */
static int mp_parse_qps(const char *arg)
{
	char str[64] = { };
	int dev_id = -1;
	const char *start = arg;
	const char *end;
	int finish = 0;

	while (1) {
		end = strchr(start, ':');
		if (end == NULL)
			return 0;
		memcpy(str, start, end - start);
		dev_id = strtol(str, NULL, 10);
		start = end + 1;
		if (*start == '\0') {
			MP_APP_LOG_2(ERR, COL_RED,
				"Parsing queue pairs: error parsing");
			return -1;
		}
		const char *curr = start;

		while (1) {
			memset(str, 0, sizeof(str));
			if (*curr == ',' || *curr == ';' || *curr == '\0') {
				memcpy(str, start, curr - start);
				int qp_id = strtol(str, NULL, 10);

				mp_app_devs[dev_id].queue_pair_flag[qp_id] =
						QP_TO_CONFIGURE;
			}
			if (*curr == ',') {
				start = curr + 1;
				curr++;
				continue;
			} else if (*curr == ';') {
				start = curr + 1;
				break;
			} else if (*curr == '\0') {
				finish = 1;
				break;
			}
			curr++;
		}
		if (finish)
			break;
	}

	return 0;
}

static int
parse_qp_config(struct mp_crypto_app_parameters *mp_params, const char *arg)
{
	strncpy(mp_params->qp_config, arg, MP_APP_QP_PARAM_LEN);
	if (mp_parse_qps(arg)) {
		MP_APP_LOG_2(ERR, COL_RED, "- Parsing error, qpairs string");
		return -1;
	}

	return 0;
}

static int
parse_enq(struct mp_crypto_app_parameters *mp_params, const char *arg)
{
	char str[64] = { };
	const char *start = arg;
	/* dev id */
	char *end = strchr(start, ':');
	int i = 0;

	if (end == NULL)
		goto err;
	memcpy(str, start, end - start);
	mp_params->enq_param.dev_id = strtol(str, NULL, 10);
	/* qp id */
	memset(str, 0, sizeof(str));
	start = end + 1;
	end = strchr(start, ':');
	if (end == NULL)
		goto err;
	memcpy(str, start, end - start);
	mp_params->enq_param.qp_id = strtol(str, NULL, 10);
	/* ops no */
	memset(str, 0, sizeof(str));
	start = end + 1;
	end = strchr(start, ':');
	if (end == NULL)
		goto err;
	memcpy(str, start, end - start);
	mp_params->enq_param.ops_no = strtol(str, NULL, 10);
	/* vector ids */
	start = end + 1;
	while ((end = strchr(start, ',')) != NULL) {
		memset(str, 0, sizeof(str));
		memcpy(str, start, end - start);
		mp_params->enq_param.vector_number[i] = strtoul(str, NULL, 0);
		start = end + 1;
		i++;
	}
	if (i == 0)
		goto err;

	MP_APP_LOG(INFO, COL_BLUE, "Run enqueue on device %d",
			mp_params->enq_param.dev_id);
	MP_APP_LOG(INFO, COL_BLUE, "Run enqueue on qp %d",
			mp_params->enq_param.qp_id);
	i = 0;
	while (mp_params->enq_param.vector_number[i] > 0 &&
			i < MP_APP_MAX_VECTORS)	{
		MP_APP_LOG(INFO, COL_BLUE, "Run enqueue vector %d",
			mp_params->enq_param.vector_number[i]);
		i++;
	}

	mp_params->enq_param.checkpoint = 1000000;

	return 0;
err:
	MP_APP_LOG_2(ERR, COL_RED, "Error parsing enq");
	return -1;
}

static int
parse_deq(struct mp_crypto_app_parameters *mp_params, const char *arg)
{
	char str[64] = { };
	const char *start = arg;
	/* Dev id */
	char *end = strchr(start, ':');
	int i = 0;

	if (end == NULL)
		goto err;
	memcpy(str, start, end - start);
	mp_params->deq_param.dev_id = strtol(str, NULL, 10);
	/* qp id */
	memset(str, 0, sizeof(str));
	start = end + 1;
	end = strchr(start, ':');
	if (end == NULL)
		goto err;
	memcpy(str, start, end - start);
	mp_params->deq_param.qp_id = strtol(str, NULL, 10);
	/* ops no */
	memset(str, 0, sizeof(str));
	start = end + 1;
	end = strchr(start, ':');
	if (end == NULL)
		goto err;
	memcpy(str, start, end - start);
	mp_params->deq_param.ops_no = strtol(str, NULL, 10);

	/* vector no */
	start = end + 1;
	while ((end = strchr(start, ',')) != NULL) {
		memset(str, 0, sizeof(str));
		memcpy(str, start, end - start);
		mp_params->deq_param.vector_number[i] = strtoul(str, NULL, 0);
		start = end + 1;
		i++;
	}
	if (i == 0)
		goto err;

	MP_APP_LOG(INFO, COL_BLUE, "Run dequeue on device %d",
			mp_params->deq_param.dev_id);
	MP_APP_LOG(INFO, COL_BLUE, "Run dequeue on qp %d",
			mp_params->deq_param.qp_id);
	i = 0;
	while (mp_params->deq_param.vector_number[i] > 0 &&
			i < MP_APP_MAX_VECTORS)	{
		MP_APP_LOG(INFO, COL_BLUE, "Run dequeue vector %d",
				mp_params->deq_param.vector_number[i]);
		i++;
	}

	mp_params->deq_param.checkpoint = 1000000;

	return 0;
err:
	MP_APP_LOG_2(ERR, COL_RED, "Error parsing deq");
	return -1;
}

static int
parse_print_stats(struct mp_crypto_app_parameters *mp_params,
			const char *arg __rte_unused)
{
	mp_params->print_stats = 1;
	return 0;
}

static int
parse_session_mask(struct mp_crypto_app_parameters *mp_params,
					const char *arg)
{
	char *end = NULL;

	mp_params->session_mask = strtoull(arg, &end, 16);

	return 0;
}

static int
parse_devtype(struct mp_crypto_app_parameters *mp_params,
					const char *arg)
{
	if (arg == NULL) {
		RTE_LOG(ERR, USER1, "--%s param argument is null\n",
			MP_DEVTYPE_NAME);
	}

	if (strlen(arg) > (sizeof(mp_params->devtype_name) - 1)) {
		RTE_LOG(ERR, USER1, "--%s different lengths\n",
			MP_DEVTYPE_NAME);
		return 0;
	}

	strlcpy(mp_params->devtype_name, arg,
			sizeof(mp_params->devtype_name));

	return 0;
};

typedef int (*option_parser_t)(struct mp_crypto_app_parameters
			*mp_params,	const char *arg);

struct long_opt_parser {
	const char *lgopt_name;
	option_parser_t parser_fn;
};

static int
opts_parse_long(int opt_idx, struct mp_crypto_app_parameters *mp_params)
{
	struct long_opt_parser parsermap[] = {
		{ MP_DEV_CONFIGURE, parse_config_dev },
		{ MP_QP_CONFIGURE, parse_qp_config },
		{ MP_ENQ, parse_enq },
		{ MP_DEQ, parse_deq },
		{ MP_PRINT_STATS, parse_print_stats },
		{ MP_SESSION_MASK, parse_session_mask },
		{ MP_DEVTYPE_NAME, parse_devtype },
	};
	unsigned int i;

	for (i = 0; i < RTE_DIM(parsermap); i++) {
		if (strncmp(lgopts[opt_idx].name, parsermap[i].lgopt_name,
				strlen(lgopts[opt_idx].name)) == 0) {
			return parsermap[i].parser_fn(mp_params, optarg);
		}
	}

	return 0;
}

int
options_parse(struct mp_crypto_app_parameters *mp_params,
					int argc, char **argv)
{
	int opt, retval;
	int opt_idx;

	while ((opt = getopt_long(argc, argv, "h", lgopts, &opt_idx))
			!= EOF) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			rte_exit(0, "Select options as above.\n");
			break;
		case 0:
			retval = opts_parse_long(opt_idx, mp_params);
			if (retval != 0)
				return retval;
			break;
		default:
			RTE_LOG(ERR, USER1, "Parse error after %s\n",
					lgopts[opt_idx].name);
			usage(argv[0]);
			return 0;
		}
	}

	return 0;
}

void
options_default(struct mp_crypto_app_parameters *mp_params)
{
	int i = 0;

	for (i = 0; i < MP_APP_MAX_VECTORS; i++) {
		mp_params->enq_param.dev_id = -1;
		mp_params->enq_param.qp_id = -1;
		mp_params->enq_param.vector_number[i] = -1;
		mp_params->deq_param.dev_id = -1;
		mp_params->deq_param.qp_id = -1;
		mp_params->deq_param.vector_number[i] = -1;
	}

	mp_params->enq_param.ops_no = 0;
	mp_params->deq_param.ops_no = 0;
	mp_params->print_stats = 0;
}

int
options_check(__rte_unused struct mp_crypto_app_parameters *mp_params)
{
	return 0;
}

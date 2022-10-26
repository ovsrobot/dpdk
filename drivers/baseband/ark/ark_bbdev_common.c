/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Atomic Rules LLC
 */

#include <string.h>

#include <rte_kvargs.h>
#include <rte_log.h>

#include "ark_bbdev_common.h"

int ark_bbdev_logtype;
RTE_LOG_REGISTER_DEFAULT(ark_bbdev_logtype, DEBUG);

static const char * const ark_bbdev_valid_params[] = {
	ARK_BBDEV_PKTDIR_ARG,
	ARK_BBDEV_PKTGEN_ARG,
	ARK_BBDEV_PKTCHKR_ARG,
	NULL
};

static inline int
process_pktdir_arg(const char *key, const char *value,
		   void *extra_args)
{
	uint32_t *u32 = extra_args;
	ARK_BBDEV_LOG(DEBUG, "key = %s, value = %s", key, value);

	*u32 = strtol(value, NULL, 0);
	ARK_BBDEV_LOG(DEBUG, "pkt_dir_v = 0x%x", *u32);
	return 0;
}

static inline int
process_file_args(const char *key, const char *value, void *extra_args)
{
	char *args = (char *)extra_args;
	ARK_BBDEV_LOG(DEBUG, "key = %s, value = %s", key, value);

	/* Open the configuration file */
	FILE *file = fopen(value, "r");
	char line[ARK_MAX_ARG_LEN];
	int  size = 0;
	int first = 1;

	if (file == NULL) {
		ARK_BBDEV_LOG(ERR, "Unable to open config file %s",
			      value);
		return -1;
	}

	while (fgets(line, sizeof(line), file)) {
		size += strlen(line);
		if (size >= ARK_MAX_ARG_LEN) {
			ARK_BBDEV_LOG(ERR, "Unable to parse file %s args, "
				      "parameter list is too long", value);
			fclose(file);
			return -1;
		}
		if (first) {
			strncpy(args, line, ARK_MAX_ARG_LEN);
			first = 0;
		} else {
			strncat(args, line, ARK_MAX_ARG_LEN);
		}
	}
	ARK_BBDEV_LOG(DEBUG, "file = %s", args);
	fclose(file);
	return 0;
}


/* Parse parameters used to create device */
int
parse_ark_bbdev_params(const char *input_args,
		       struct ark_bbdevice *ark_bb)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	if (ark_bb == NULL)
		return -EINVAL;
	if (input_args == NULL)
		return ret;

	kvlist = rte_kvargs_parse(input_args, ark_bbdev_valid_params);
	if (kvlist == NULL)
		return -EFAULT;

	ret = rte_kvargs_process(kvlist, ARK_BBDEV_PKTDIR_ARG,
				  &process_pktdir_arg, &ark_bb->pkt_dir_v);
	if (ret < 0)
		goto exit;

	ret = rte_kvargs_process(kvlist, ARK_BBDEV_PKTGEN_ARG,
				 &process_file_args, &ark_bb->pkt_gen_args);
	if (ret < 0)
		goto exit;

	ret = rte_kvargs_process(kvlist, ARK_BBDEV_PKTCHKR_ARG,
				 &process_file_args, &ark_bb->pkt_chkr_args);
	if (ret < 0)
		goto exit;

 exit:
	if (kvlist)
		rte_kvargs_free(kvlist);
	return ret;
}

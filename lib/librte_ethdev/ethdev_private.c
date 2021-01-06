/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Gaëtan Rivet
 */

#include "rte_ethdev.h"
#include "rte_ethdev_driver.h"
#include "ethdev_private.h"

uint16_t
eth_dev_to_id(const struct rte_eth_dev *dev)
{
	if (dev == NULL)
		return RTE_MAX_ETHPORTS;
	return dev - rte_eth_devices;
}

struct rte_eth_dev *
eth_find_device(const struct rte_eth_dev *start, rte_eth_cmp_t cmp,
		const void *data)
{
	struct rte_eth_dev *edev;
	ptrdiff_t idx;

	/* Avoid Undefined Behaviour */
	if (start != NULL &&
	    (start < &rte_eth_devices[0] ||
	     start > &rte_eth_devices[RTE_MAX_ETHPORTS]))
		return NULL;
	if (start != NULL)
		idx = eth_dev_to_id(start) + 1;
	else
		idx = 0;
	for (; idx < RTE_MAX_ETHPORTS; idx++) {
		edev = &rte_eth_devices[idx];
		if (cmp(edev, data) == 0)
			return edev;
	}
	return NULL;
}

static int
rte_eth_devargs_process_range(char *str, uint16_t *list, uint16_t *len_list,
	const uint16_t max_list)
{
	uint16_t lo, hi, val;
	int result;
	char *pos = str;

	result = sscanf(str, "%hu-%hu", &lo, &hi);
	if (result == 1) {
		if (*len_list >= max_list)
			return -ENOMEM;
		list[(*len_list)++] = lo;
	} else if (result == 2) {
		if (lo >= hi)
			return -EINVAL;
		for (val = lo; val <= hi; val++) {
			if (*len_list >= max_list)
				return -ENOMEM;
			list[(*len_list)++] = val;
		}
	} else
		return -EINVAL;
	while (*pos != 0 && ((*pos >= '0' && *pos <= '9') || *pos == '-'))
		pos++;
	return pos - str;
}

static int
rte_eth_devargs_process_list(char *str, uint16_t *list, uint16_t *len_list,
	const uint16_t max_list)
{
	char *pos = str;
	int ret;

	if (*pos == '[')
		pos++;
	while (1) {
		ret = rte_eth_devargs_process_range(pos, list, len_list,
						    max_list);
		if (ret < 0)
			return ret;
		pos += ret;
		if (*pos != ',') /* end of list */
			break;
		pos++;
	}
	if (*str == '[' && *pos != ']')
		return -EINVAL;
	if (*pos == ']')
		pos++;
	return pos - str;
}

/*
 * representor format:
 *   #: range or single number of VF representor - legacy
 */
int
rte_eth_devargs_parse_representor_ports(char *str, void *data)
{
	struct rte_eth_devargs *eth_da = data;
	int ret;

	/* Number # alone implies VF */
	eth_da->type = RTE_ETH_REPRESENTOR_VF;
	ret = rte_eth_devargs_process_list(str, eth_da->representor_ports,
		&eth_da->nb_representor_ports, RTE_MAX_ETHPORTS);
	if (ret < 0)
		RTE_LOG(ERR, EAL, "wrong representor format: %s\n", str);
	return ret < 0 ? ret : 0;
}

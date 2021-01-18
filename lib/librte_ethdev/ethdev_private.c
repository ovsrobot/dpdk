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
rte_eth_devargs_enlist(uint16_t *list, uint16_t *len_list,
		       const uint16_t max_list, uint16_t val)
{
	uint16_t i;

	if (*len_list >= max_list)
		return -1;
	for (i = 0; i < *len_list; i++) {
		if (list[i] == val)
			return 0;
	}
	list[(*len_list)++] = val;
	return 0;
}

static char *
rte_eth_devargs_process_range(char *str, uint16_t *list, uint16_t *len_list,
	const uint16_t max_list)
{
	uint16_t lo, hi, val;
	int result;
	char *pos = str;

	result = sscanf(str, "%hu-%hu", &lo, &hi);
	if (result == 1) {
		if (rte_eth_devargs_enlist(list, len_list, max_list, lo) != 0)
			return NULL;
	} else if (result == 2) {
		if (lo >= hi)
			return NULL;
		for (val = lo; val <= hi; val++) {
			if (rte_eth_devargs_enlist(list, len_list, max_list,
						   val) != 0)
				return NULL;
		}
	} else
		return NULL;
	while (*pos != 0 && ((*pos >= '0' && *pos <= '9') || *pos == '-'))
		pos++;
	return pos;
}

static char *
rte_eth_devargs_process_list(char *str, uint16_t *list, uint16_t *len_list,
	const uint16_t max_list)
{
	char *pos = str;

	if (*pos == '[')
		pos++;
	while (1) {
		pos = rte_eth_devargs_process_range(pos, list, len_list,
						    max_list);
		if (pos == NULL)
			return NULL;
		if (*pos != ',') /* end of list */
			break;
		pos++;
	}
	if (*str == '[' && *pos != ']')
		return NULL;
	if (*pos == ']')
		pos++;
	return pos;
}

/*
 * representor format:
 *   #: range or single number of VF representor - legacy
 *   [[c#]pf#]vf#: VF port representor/s
 *   [[c#]pf#]sf#: SF port representor/s
 */
int
rte_eth_devargs_parse_representor_ports(char *str, void *data)
{
	struct rte_eth_devargs *eth_da = data;

	if (str[0] == 'c') {
		str += 1;
		str = rte_eth_devargs_process_list(str, eth_da->mh_controllers,
				&eth_da->nb_mh_controllers,
				RTE_DIM(eth_da->mh_controllers));
		if (str == NULL)
			goto err;
	}
	if (str[0] == 'p' && str[1] == 'f') {
		eth_da->type = RTE_ETH_REPRESENTOR_PF;
		str += 2;
		str = rte_eth_devargs_process_list(str, eth_da->ports,
				&eth_da->nb_ports, RTE_MAX_ETHPORTS);
		if (str == NULL)
			goto err;
	}
	if (str[0] == 'v' && str[1] == 'f') {
		eth_da->type = RTE_ETH_REPRESENTOR_VF;
		str += 2;
	} else if (str[0] == 's' && str[1] == 'f') {
		eth_da->type = RTE_ETH_REPRESENTOR_SF;
		str += 2;
	} else {
		eth_da->type = RTE_ETH_REPRESENTOR_VF;
	}
	str = rte_eth_devargs_process_list(str, eth_da->representor_ports,
		&eth_da->nb_representor_ports, RTE_MAX_ETHPORTS);
err:
	if (str == NULL)
		RTE_LOG(ERR, EAL, "wrong representor format: %s\n", str);
	return str == NULL ? -1 : 0;
}

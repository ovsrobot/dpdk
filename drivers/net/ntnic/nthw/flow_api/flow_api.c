/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <arpa/inet.h> /* htons, htonl, ntohs */

#include "ntlog.h"

#include "flow_api.h"

#include "flow_api_nic_setup.h"
#include "stream_binary_flow_api.h"
#include "flow_api_actions.h"
#include "flow_api_backend.h"
#include "flow_api_engine.h"

#include "flow_api_profile_inline.h"

#define SCATTER_GATHER

const char *dbg_res_descr[] = {
	/* RES_QUEUE */ "RES_QUEUE",
	/* RES_CAT_CFN */ "RES_CAT_CFN",
	/* RES_CAT_COT */ "RES_CAT_COT",
	/* RES_CAT_EXO */ "RES_CAT_EXO",
	/* RES_CAT_LEN */ "RES_CAT_LEN",
	/* RES_KM_FLOW_TYPE */ "RES_KM_FLOW_TYPE",
	/* RES_KM_CATEGORY */ "RES_KM_CATEGORY",
	/* RES_HSH_RCP */ "RES_HSH_RCP",
	/* RES_PDB_RCP */ "RES_PDB_RCP",
	/* RES_QSL_RCP */ "RES_QSL_RCP",
	/* RES_QSL_LTX */ "RES_QSL_LTX",
	/* RES_QSL_QST */ "RES_QSL_QST",
	/* RES_SLC_RCP */ "RES_SLC_RCP",
	/* RES_IOA_RCP */ "RES_IOA_RCP",
	/* RES_ROA_RCP */ "RES_ROA_RCP",
	/* RES_FLM_FLOW_TYPE */ "RES_FLM_FLOW_TYPE",
	/* RES_FLM_RCP */ "RES_FLM_RCP",
	/* RES_HST_RCP */ "RES_HST_RCP",
	/* RES_TPE_RCP */ "RES_TPE_RCP",
	/* RES_TPE_EXT */ "RES_TPE_EXT",
	/* RES_TPE_RPL */ "RES_TPE_RPL",
	/* RES_COUNT */ "RES_COUNT",
	/* RES_INVALID */ "RES_INVALID"
};

static struct flow_nic_dev *dev_base;
static pthread_mutex_t base_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * *****************************************************************************
 * Error handling
 * *****************************************************************************
 */

static const struct {
	const char *message;
} err_msg[] = {
	/* 00 */ { "Operation successfully completed" },
	/* 01 */ { "Operation failed" },
	/* 02 */ { "Memory allocation failed" },
	/* 03 */ { "Too many output destinations" },
	/* 04 */ { "Too many output queues for RSS" },
	/* 05 */ { "The VLAN TPID specified is not supported" },
	/* 06 */ { "The VxLan Push header specified is not accepted" },
	/* 07 */
	{ "While interpreting VxLan Pop action, could not find a destination port" },
	/* 08 */ { "Failed in creating a HW-internal VTEP port" },
	/* 09 */ { "Too many VLAN tag matches" },
	/* 10 */ { "IPv6 invalid header specified" },
	/* 11 */ { "Too many tunnel ports. HW limit reached" },
	/* 12 */ { "Unknown or unsupported flow match element received" },
	/* 13 */ { "Match failed because of HW limitations" },
	/* 14 */ { "Match failed because of HW resource limitations" },
	/* 15 */ { "Match failed because of too complex element definitions" },
	/* 16 */ { "Action failed. To too many output destinations" },
	/* 17 */ { "Action Output failed, due to HW resource exhaustion" },
	/* 18 */
	{ "Push Tunnel Header action cannot output to multiple destination queues" },
	/* 19 */ { "Inline action HW resource exhaustion" },
	/* 20 */ { "Action retransmit/recirculate HW resource exhaustion" },
	/* 21 */ { "Flow counter HW resource exhaustion" },
	/* 22 */ { "Internal HW resource exhaustion to handle Actions" },
	/* 23 */ { "Internal HW QSL compare failed" },
	/* 24 */ { "Internal CAT CFN reuse failed" },
	/* 25 */ { "Match variations too complex" },
	/* 26 */ { "Match failed because of CAM/TCAM full" },
	/* 27 */ { "Internal creation of a tunnel end point port failed" },
	/* 28 */ { "Unknown or unsupported flow action received" },
	/* 29 */ { "Removing flow failed" },
	/* 30 */
	{ "No output queue specified. Ignore this flow offload and uses default queue" },
	/* 31 */ { "No output queue found" },
	/* 32 */ { "Unsupported EtherType or rejected caused by offload policy" },
	/* 33 */
	{ "Destination port specified is invalid or not reachable from this NIC" },
	/* 34 */ { "Partial offload is not supported in this configuration" },
	/* 35 */ { "Match failed because of CAT CAM exhausted" },
	/* 36 */
	{ "Match failed because of CAT CAM Key clashed with an existing KCC Key" },
	/* 37 */ { "Match failed because of CAT CAM write failed" },
	/* 38 */ { "Partial flow mark too big for device" },
	/* 39 */  {"Invalid priority value"},
};

void flow_nic_set_error(enum flow_nic_err_msg_e msg, struct flow_error *error)
{
	assert(msg < ERR_MSG_NO_MSG);
	if (error) {
		error->message = err_msg[msg].message;
		error->type = (msg == ERR_SUCCESS) ? FLOW_ERROR_SUCCESS :
			      FLOW_ERROR_GENERAL;
	}
}

/*
 * *****************************************************************************
 * Resources
 * *****************************************************************************
 */

int flow_nic_alloc_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			    uint32_t alignment)
{
	for (unsigned int i = 0; i < ndev->res[res_type].resource_count;
			i += alignment) {
		if (!flow_nic_is_resource_used(ndev, res_type, i)) {
			flow_nic_mark_resource_used(ndev, res_type, i);
			ndev->res[res_type].ref[i] = 1;
			return i;
		}
	}
	return -1;
}

int flow_nic_alloc_resource_index(struct flow_nic_dev *ndev, int idx,
				  enum res_type_e res_type)
{
	if (!flow_nic_is_resource_used(ndev, res_type, idx)) {
		flow_nic_mark_resource_used(ndev, res_type, idx);
		ndev->res[res_type].ref[idx] = 1;
		return 0;
	}
	return -1;
}

int flow_nic_alloc_resource_contig(struct flow_nic_dev *ndev,
				   enum res_type_e res_type, unsigned int num,
				   uint32_t alignment)
{
	unsigned int idx_offs;

	for (unsigned int res_idx = 0;
			res_idx < ndev->res[res_type].resource_count - (num - 1);
			res_idx += alignment) {
		if (!flow_nic_is_resource_used(ndev, res_type, res_idx)) {
			for (idx_offs = 1; idx_offs < num; idx_offs++) {
				if (flow_nic_is_resource_used(ndev, res_type,
							      res_idx + idx_offs))
					break;
			}
			if (idx_offs < num)
				continue;

			/* found a contiguous number of "num" res_type elements - allocate them */
			for (idx_offs = 0; idx_offs < num; idx_offs++) {
				flow_nic_mark_resource_used(ndev, res_type,
							    res_idx + idx_offs);
				ndev->res[res_type].ref[res_idx + idx_offs] = 1;
			}
			return res_idx;
		}
	}
	return -1;
}

void flow_nic_free_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			    int idx)
{
	flow_nic_mark_resource_unused(ndev, res_type, idx);
}

int flow_nic_ref_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			  int index)
{
	NT_LOG(DBG, FILTER,
	       "Reference resource %s idx %i (before ref cnt %i)\n",
	       dbg_res_descr[res_type], index, ndev->res[res_type].ref[index]);
	assert(flow_nic_is_resource_used(ndev, res_type, index));
	if (ndev->res[res_type].ref[index] == (uint32_t)-1)
		return -1;
	ndev->res[res_type].ref[index]++;
	return 0;
}

int flow_nic_deref_resource(struct flow_nic_dev *ndev, enum res_type_e res_type,
			    int index)
{
	NT_LOG(DBG, FILTER,
	       "De-reference resource %s idx %i (before ref cnt %i)\n",
	       dbg_res_descr[res_type], index, ndev->res[res_type].ref[index]);
	assert(flow_nic_is_resource_used(ndev, res_type, index));
	assert(ndev->res[res_type].ref[index]);
	/* deref */
	ndev->res[res_type].ref[index]--;
	if (!ndev->res[res_type].ref[index])
		flow_nic_free_resource(ndev, res_type, index);
	return !!ndev->res[res_type]
	       .ref[index]; /* if 0 resource has been freed */
}

int flow_nic_find_next_used_resource(struct flow_nic_dev *ndev,
				     enum res_type_e res_type, int idx_start)
{
	for (unsigned int i = idx_start; i < ndev->res[res_type].resource_count;
			i++) {
		if (flow_nic_is_resource_used(ndev, res_type, i))
			return i;
	}
	return -1;
}

/*
 * Allocate a number flow resources.
 *
 * Arguments:
 *   ndev       : device
 *   res_type   : resource type
 *   fh         : flow handle
 *   count      : number of (contiguous) resources to be allocated
 *   alignment  : start index alignment
 *                  1: the allocation can start at any index
 *                  2: the allocation must start at index modulus 2 (0, 2, 4, 6, ...)
 *                  3: the allocation must start at index modulus 3 (0, 3, 6, 9, ...)
 *                  etc.
 * Returns:
 *          0   : success
 *         -1   : failure
 */
int flow_nic_allocate_fh_resource(struct flow_nic_dev *ndev,
				  enum res_type_e res_type,
				  struct flow_handle *fh, uint32_t count,
				  uint32_t alignment)
{
	if (count > 1) {
		/* Contiguous */
		fh->resource[res_type].index =
			flow_nic_alloc_resource_contig(ndev, res_type, count, alignment);
	} else {
		fh->resource[res_type].index =
			flow_nic_alloc_resource(ndev, res_type, alignment);
	}

	if (fh->resource[res_type].index < 0)
		return -1;
	fh->resource[res_type].count = count;
	return 0;
}

int flow_nic_allocate_fh_resource_index(struct flow_nic_dev *ndev,
					enum res_type_e res_type, int idx,
					struct flow_handle *fh)
{
	int err = flow_nic_alloc_resource_index(ndev, idx, res_type);

	if (err)
		return err;

	fh->resource[res_type].index = idx;
	if (fh->resource[res_type].index < 0)
		return -1;
	fh->resource[res_type].count = 1;
	return 0;
}

/*
 * *****************************************************************************
 * Hash
 * *****************************************************************************
 */

int flow_nic_set_hasher(struct flow_nic_dev *ndev, int hsh_idx,
			enum flow_nic_hash_e algorithm)
{
	hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_PRESET_ALL, hsh_idx, 0, 0);
	switch (algorithm) {
	case HASH_ALGO_5TUPLE:
		/* need to create an IPv6 hashing and enable the adaptive ip mask bit */
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_LOAD_DIST_TYPE,
				   hsh_idx, 0, 2);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW0_PE, hsh_idx, 0,
				   DYN_FINAL_IP_DST);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW0_OFS, hsh_idx, 0,
				   -16);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW4_PE, hsh_idx, 0,
				   DYN_FINAL_IP_DST);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW4_OFS, hsh_idx, 0,
				   0);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W8_PE, hsh_idx, 0,
				   DYN_L4);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W8_OFS, hsh_idx, 0, 0);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W9_PE, hsh_idx, 0, 0);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W9_OFS, hsh_idx, 0, 0);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W9_P, hsh_idx, 0, 0);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_P_MASK, hsh_idx, 0, 1);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 0,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 1,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 2,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 3,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 4,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 5,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 6,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 7,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 8,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 9,
				   0);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_SEED, hsh_idx, 0,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_HSH_VALID, hsh_idx, 0,
				   1);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_HSH_TYPE, hsh_idx, 0,
				   HASH_5TUPLE);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_AUTO_IPV4_MASK,
				   hsh_idx, 0, 1);

		NT_LOG(DBG, FILTER,
		       "Set IPv6 5-tuple hasher with adaptive IPv4 hashing\n");
		break;
	default:
	case HASH_ALGO_ROUND_ROBIN:
		/* zero is round-robin */
		break;
	}

	return 0;
}

int flow_nic_set_hasher_fields(struct flow_nic_dev *ndev, int hsh_idx,
			       struct nt_eth_rss f)
{
	uint64_t fields = f.fields;

	int res = 0;

	res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_PRESET_ALL, hsh_idx, 0,
				  0);
	res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_LOAD_DIST_TYPE, hsh_idx,
				  0, 2);
	switch (fields) {
	case NT_ETH_RSS_C_VLAN:
		/*
		 * Here we are using 1st VLAN to point C-VLAN which is only try for the single VLAN
		 * provider
		 */
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W8_PE, hsh_idx,
					  0, DYN_FIRST_VLAN);
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_W8_OFS, hsh_idx,
					  0, 0);
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK,
					  hsh_idx, 8, 0xffffffff);
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_HSH_TYPE,
					  hsh_idx, 0, HASH_LAST_VLAN_ID);
		if (res) {
			NT_LOG(ERR, FILTER,
			       "VLAN hasher is not set hardware communication problem has "
			       "occurred. The cardware could be in inconsistent state. Rerun.\n");
			return -1;
		}
		NT_LOG(DBG, FILTER, "Set VLAN hasher.\n");
		return 0;
	case NT_ETH_RSS_LEVEL_OUTERMOST | NT_ETH_RSS_L3_DST_ONLY | NT_ETH_RSS_IP:
		/* need to create an IPv6 hashing and enable the adaptive ip mask bit */
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW4_PE, hsh_idx, 0,
				   DYN_FINAL_IP_DST);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW4_OFS, hsh_idx, 0,
				   0);

		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 4,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 5,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 6,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 7,
				   0xffffffff);

		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_HSH_TYPE, hsh_idx, 0,
				   HASH_OUTER_DST_IP);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_AUTO_IPV4_MASK,
				   hsh_idx, 0, 1);
		if (res) {
			NT_LOG(ERR, FILTER,
			       "Outer dst IP hasher is not set hardware communication problem has "
			       "occurred. The cardware could be in inconsistent state. Rerun.\n");
			return -1;
		}
		NT_LOG(DBG, FILTER, "Set outer dst IP hasher.\n");
		return 0;
	case NT_ETH_RSS_LEVEL_INNERMOST | NT_ETH_RSS_L3_SRC_ONLY | NT_ETH_RSS_IP:
		/* need to create an IPv6 hashing and enable the adaptive ip mask bit */
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW0_PE, hsh_idx, 0,
				   DYN_TUN_FINAL_IP_DST);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_QW0_OFS, hsh_idx, 0,
				   -16);

		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 0,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 1,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 2,
				   0xffffffff);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx, 3,
				   0xffffffff);

		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_HSH_TYPE, hsh_idx, 0,
				   HASH_INNER_SRC_IP);
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_AUTO_IPV4_MASK,
				   hsh_idx, 0, 1);
		if (res) {
			NT_LOG(ERR, FILTER,
			       "Inner (depth = 1) src IP hasher is not set hardware communication "
			       "problem has occurred. The cardware could be in inconsistent state. "
			       "Rerun.\n");
			return -1;
		}
		NT_LOG(DBG, FILTER, "Set outer dst IP hasher.\n");
		return 0;
	default:
		NT_LOG(ERR, FILTER,
		       "RSS bit flags can't be set up. "
		       "Flags combination is not supported.");
		return -1;
	}
}

/*
 * *****************************************************************************
 * Nic port/adapter lookup
 * *****************************************************************************
 */

struct flow_eth_dev *nic_and_port_to_eth_dev(uint8_t adapter_no, uint8_t port)
{
	struct flow_nic_dev *nic_dev = dev_base;

	while (nic_dev) {
		if (nic_dev->adapter_no == adapter_no)
			break;
		nic_dev = nic_dev->next;
	}

	if (!nic_dev)
		return NULL;

	struct flow_eth_dev *dev = nic_dev->eth_base;

	while (dev) {
		if (port == dev->port)
			return dev;
		dev = dev->next;
	}

	return NULL;
}

struct flow_nic_dev *get_nic_dev_from_adapter_no(uint8_t adapter_no)
{
	struct flow_nic_dev *ndev = dev_base;

	while (ndev) {
		if (adapter_no == ndev->adapter_no)
			break;
		ndev = ndev->next;
	}
	return ndev;
}

/*
 * *****************************************************************************
 * LAG control implementation
 * *****************************************************************************
 */

int lag_set_port_group(uint8_t adapter_no, uint32_t port_mask)
{
	pthread_mutex_lock(&base_mtx);
	struct flow_nic_dev *ndev = get_nic_dev_from_adapter_no(adapter_no);

	if (!ndev) {
		/* Error invalid nic device */
		pthread_mutex_unlock(&base_mtx);
		return -1;
	}
	/*
	 * Sets each 2 ports for each bit N as Lag. Ports N*2+N*2+1 are merged together
	 * and reported as N*2 incoming port
	 */
	hw_mod_rmc_ctrl_set(&ndev->be, HW_RMC_LAG_PHY_ODD_EVEN, port_mask);
	hw_mod_rmc_ctrl_flush(&ndev->be);
	pthread_mutex_unlock(&base_mtx);
	return 0;
}

int lag_set_port_block(uint8_t adapter_no, uint32_t port_mask)
{
	pthread_mutex_lock(&base_mtx);
	struct flow_nic_dev *ndev = get_nic_dev_from_adapter_no(adapter_no);

	if (!ndev) {
		/* Error invalid nic device */
		pthread_mutex_unlock(&base_mtx);
		return -1;
	}
	/* Blocks for traffic from port */
	hw_mod_rmc_ctrl_set(&ndev->be, HW_RMC_BLOCK_MAC_PORT, port_mask);
	hw_mod_rmc_ctrl_flush(&ndev->be);
	pthread_mutex_unlock(&base_mtx);
	return 0;
}

static void write_lag_entry(struct flow_api_backend_s *be, uint32_t index,
			    uint32_t value)
{
	hw_mod_roa_lagcfg_set(be, HW_ROA_LAGCFG_TXPHY_PORT, index, value);
	hw_mod_roa_lagcfg_flush(be, index, 1);
}

int lag_set_config(uint8_t adapter_no, enum flow_lag_cmd cmd, uint32_t index,
		   uint32_t value)
{
	pthread_mutex_lock(&base_mtx);
	struct flow_nic_dev *ndev = get_nic_dev_from_adapter_no(adapter_no);

	if (!ndev) {
		/* Error invalid nic device */
		pthread_mutex_unlock(&base_mtx);
		return -1;
	}

	switch (cmd) {
	case FLOW_LAG_SET_ENTRY:
		write_lag_entry(&ndev->be, index, value);
		break;

	case FLOW_LAG_SET_ALL:
		index &= 3;
		for (unsigned int i = 0; i < ndev->be.roa.nb_lag_entries;
				i += 4)
			write_lag_entry(&ndev->be, i + index, value);
		break;

	case FLOW_LAG_SET_BALANCE:
		/*
		 * This function will balance the output port
		 * value: The balance of the distribution:
		 * port  P0 / P1
		 * 0:    0  / 100    port 0 is disabled
		 * 25:   25 / 75
		 * 50:   50 / 50
		 * 75:   75 / 25
		 * 100:  100/  0     port 1 is disabled
		 */
	{
		/* Clamp the balance to 100% output on port 1 */
		if (value > 100)
			value = 100;
		double balance = ((double)value / 100.0);
		double block_count =
			(double)ndev->be.roa.nb_lag_entries / 4.0;

		int output_port = 1;
		int port0_output_block_count =
			(int)(block_count * balance);

		for (int block = 0; block < block_count; block++) {
			/* When the target port0 balance is reached. */
			if (block >= port0_output_block_count)
				output_port = 2;
			/* Write an entire hash block to a given output port. */
			for (int idx = 0; idx < 4; idx++) {
				write_lag_entry(&ndev->be,
						block * 4 + idx,
						output_port);
			} /* for each index in hash block */
		} /* for each hash block */
	}

	break;
	default:
		pthread_mutex_unlock(&base_mtx);
		return -1;
	}

	pthread_mutex_unlock(&base_mtx);
	return 0;
}

/*
 * *****************************************************************************
 * Flow API
 * *****************************************************************************
 */

int flow_validate(struct flow_eth_dev *dev, const struct flow_elem item[],
		  const struct flow_action action[], struct flow_error *error)
{
	if (dev->ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
		NT_LOG(ERR, FILTER, "vSwitch profile not supported");
		return -1;
	}
	return flow_validate_profile_inline(dev, item, action, error);
}

struct flow_handle *flow_create(struct flow_eth_dev *dev,
				const struct flow_attr *attr,
				const struct flow_elem item[],
				const struct flow_action action[],
				struct flow_error *error)
{
	if (dev->ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
		NT_LOG(ERR, FILTER, "vSwitch profile not supported");
		return NULL;
	}
	return flow_create_profile_inline(dev, attr, item, action, error);
}

int flow_destroy(struct flow_eth_dev *dev, struct flow_handle *flow,
		 struct flow_error *error)
{
	if (dev->ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
		NT_LOG(ERR, FILTER, "vSwitch profile not supported");
		return -1;
	}
	return flow_destroy_profile_inline(dev, flow, error);
}

int flow_flush(struct flow_eth_dev *dev, struct flow_error *error)
{
	if (dev->ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
		NT_LOG(ERR, FILTER, "vSwitch profile not supported");
		return -1;
	}
	return flow_flush_profile_inline(dev, error);
}

int flow_query(struct flow_eth_dev *dev, struct flow_handle *flow,
	       const struct flow_action *action, void **data, uint32_t *length,
	       struct flow_error *error)
{
	if (dev->ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
		NT_LOG(ERR, FILTER, "vSwitch profile not supported");
		return -1;
	}
	return flow_query_profile_inline(dev, flow, action, data, length,
					 error);
}

/*
 * *****************************************************************************
 * Device Management API
 * *****************************************************************************
 */

static void nic_insert_eth_port_dev(struct flow_nic_dev *ndev,
				    struct flow_eth_dev *dev)
{
	dev->next = ndev->eth_base;
	ndev->eth_base = dev;
}

static int nic_remove_eth_port_dev(struct flow_nic_dev *ndev,
				   struct flow_eth_dev *eth_dev)
{
	struct flow_eth_dev *dev = ndev->eth_base, *prev = NULL;

	while (dev) {
		if (dev == eth_dev) {
			if (prev)
				prev->next = dev->next;

			else
				ndev->eth_base = dev->next;
			return 0;
		}
		prev = dev;
		dev = dev->next;
	}
	return -1;
}

static void flow_ndev_reset(struct flow_nic_dev *ndev)
{
	/* Delete all eth-port devices created on this NIC device */
	while (ndev->eth_base)
		flow_delete_eth_dev(ndev->eth_base);

	/* Error check */
	while (ndev->flow_base) {
		NT_LOG(ERR, FILTER,
		       "ERROR : Flows still defined but all eth-ports deleted. Flow %p\n",
		       ndev->flow_base);

		if (ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH)  {
			NT_LOG(ERR, FILTER, "vSwitch profile not supported");
			return;
		}
		flow_destroy_profile_inline(ndev->flow_base->dev,
					    ndev->flow_base, NULL);
	}

	if (ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
		NT_LOG(ERR, FILTER, "vSwitch profile not supported");
		return;
	}
	done_flow_management_of_ndev_profile_inline(ndev);

	km_free_ndev_resource_management(&ndev->km_res_handle);
	kcc_free_ndev_resource_management(&ndev->kcc_res_handle);

#ifdef FLOW_DEBUG
	/*
	 * free all resources default allocated, initially for this NIC DEV
	 * Is not really needed since the bitmap will be freed in a sec. Therefore
	 * only in debug mode
	 */

	/* Check if all resources has been released */
	NT_LOG(DBG, FILTER, "Delete NIC DEV Adaptor %i\n", ndev->adapter_no);
	for (unsigned int i = 0; i < RES_COUNT; i++) {
		int err = 0;
#if defined(FLOW_DEBUG)
		NT_LOG(DBG, FILTER, "RES state for: %s\n", dbg_res_descr[i]);
#endif
		for (unsigned int ii = 0; ii < ndev->res[i].resource_count;
				ii++) {
			int ref = ndev->res[i].ref[ii];
			int used = flow_nic_is_resource_used(ndev, i, ii);

			if (ref || used) {
				NT_LOG(DBG, FILTER,
				       "  [%i]: ref cnt %i, used %i\n", ii, ref,
				       used);
				err = 1;
			}
		}
		if (err)
			NT_LOG(DBG, FILTER,
			       "ERROR - some resources not freed\n");
	}
#endif
}

int flow_reset_nic_dev(uint8_t adapter_no)
{
	struct flow_nic_dev *ndev = get_nic_dev_from_adapter_no(adapter_no);

	if (!ndev)
		return -1;
	flow_ndev_reset(ndev);
	flow_api_backend_reset(&ndev->be);
	return 0;
}

/*
 * adapter_no       physical adapter no
 * port_no          local port no
 * alloc_rx_queues  number of rx-queues to allocate for this eth_dev
 */
struct flow_eth_dev *flow_get_eth_dev(uint8_t adapter_no, uint8_t port_no,
				      uint32_t port_id, int alloc_rx_queues,
				      struct flow_queue_id_s queue_ids[],
				      int *rss_target_id,
				      enum flow_eth_dev_profile flow_profile,
				      uint32_t exception_path)
{
	int i;
	struct flow_eth_dev *eth_dev = NULL;

	NT_LOG(DBG, FILTER,
	       "Get eth-port adapter %i, port %i, port_id %u, rx queues %i, profile %i\n",
	       adapter_no, port_no, port_id, alloc_rx_queues, flow_profile);

	if (MAX_OUTPUT_DEST < FLOW_MAX_QUEUES) {
		assert(0);
		NT_LOG(ERR, FILTER,
		       "ERROR: Internal array for multiple queues too small for API\n");
	}

	pthread_mutex_lock(&base_mtx);
	struct flow_nic_dev *ndev = get_nic_dev_from_adapter_no(adapter_no);

	if (!ndev) {
		/* Error - no flow api found on specified adapter */
		NT_LOG(ERR, FILTER,
		       "ERROR: no flow interface registered for adapter %d\n",
		       adapter_no);
		pthread_mutex_unlock(&base_mtx);
		return NULL;
	}

	if (ndev->ports < ((uint16_t)port_no + 1)) {
		NT_LOG(ERR, FILTER,
		       "ERROR: port exceeds supported port range for adapter\n");
		pthread_mutex_unlock(&base_mtx);
		return NULL;
	}

	if ((alloc_rx_queues - 1) >
			FLOW_MAX_QUEUES) { /* 0th is exception so +1 */
		NT_LOG(ERR, FILTER,
		       "ERROR: Exceeds supported number of rx queues per eth device\n");
		pthread_mutex_unlock(&base_mtx);
		return NULL;
	}

	/* don't accept multiple eth_dev's on same NIC and same port */
	eth_dev = nic_and_port_to_eth_dev(adapter_no, port_no);
	if (eth_dev) {
		NT_LOG(DBG, FILTER,
		       "Re-opening existing NIC port device: NIC DEV: %i Port %i\n",
		       adapter_no, port_no);
		pthread_mutex_unlock(&base_mtx);
		flow_delete_eth_dev(eth_dev);
		eth_dev = NULL;
	}

	eth_dev = calloc(1, sizeof(struct flow_eth_dev));
	if (!eth_dev) {
		NT_LOG(ERR, FILTER, "ERROR: calloc failed\n");
		goto err_exit1;
	}

	pthread_mutex_lock(&ndev->mtx);

	eth_dev->ndev = ndev;
	eth_dev->port = port_no;
	eth_dev->port_id = port_id;

#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev,
				       FLOW_BACKEND_DEBUG_MODE_WRITE);
#endif

	/* First time then NIC is initialized */
	if (!ndev->flow_mgnt_prepared) {
		ndev->flow_profile = flow_profile;
		/* Initialize modules if needed - recipe 0 is used as no-match and must be setup */
		if (ndev->flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH) {
			NT_LOG(ERR, FILTER, "vSwitch profile not supported");
			goto err_exit0;
		} else if (initialize_flow_management_of_ndev_profile_inline(ndev)
			!= 0) {
			goto err_exit0;
		}
	} else {
		/* check if same flow type is requested, otherwise fail */
		if (ndev->flow_profile != flow_profile) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Different flow types requested on same NIC device. "
			       "Not supported.\n");
			goto err_exit0;
		}
	}

	/* Allocate the requested queues in HW for this dev */

	for (i = 0; i < alloc_rx_queues; i++) {
#ifdef SCATTER_GATHER
		eth_dev->rx_queue[i] = queue_ids[i];
#else
		int queue_id = flow_nic_alloc_resource(ndev, RES_QUEUE, 1);

		if (queue_id < 0) {
			NT_LOG(ERR, FILTER,
			       "ERROR: no more free queue IDs in NIC\n");
			goto err_exit0;
		}

		eth_dev->rx_queue[eth_dev->num_queues].id = (uint8_t)queue_id;
		eth_dev->rx_queue[eth_dev->num_queues].hw_id =
			ndev->be.iface->alloc_rx_queue(ndev->be.be_dev,
				eth_dev->rx_queue[eth_dev->num_queues].id);
		if (eth_dev->rx_queue[eth_dev->num_queues].hw_id < 0) {
			NT_LOG(ERR, FILTER,
			       "ERROR: could not allocate a new queue\n");
			goto err_exit0;
		}

		if (queue_ids) {
			queue_ids[eth_dev->num_queues] =
				eth_dev->rx_queue[eth_dev->num_queues];
		}
#endif
		if (i == 0 && (flow_profile == FLOW_ETH_DEV_PROFILE_VSWITCH ||
				(flow_profile == FLOW_ETH_DEV_PROFILE_INLINE &&
				 exception_path))) {
			/*
			 * Init QSL UNM - unmatched - redirects otherwise discarded packets in QSL
			 */
			if (hw_mod_qsl_unmq_set(&ndev->be,
						HW_QSL_UNMQ_DEST_QUEUE,
						eth_dev->port,
						eth_dev->rx_queue[0].hw_id) < 0)
				goto err_exit0;
			if (hw_mod_qsl_unmq_set(&ndev->be, HW_QSL_UNMQ_EN,
						eth_dev->port, 1) < 0)
				goto err_exit0;
			if (hw_mod_qsl_unmq_flush(&ndev->be, eth_dev->port, 1) <
					0)
				goto err_exit0;
		}

		eth_dev->num_queues++;
	}

	eth_dev->rss_target_id = -1;

	if (flow_profile == FLOW_ETH_DEV_PROFILE_INLINE) {
		for (i = 0; i < eth_dev->num_queues; i++) {
			uint32_t qen_value = 0;
			uint32_t queue_id =
				(uint32_t)eth_dev->rx_queue[i].hw_id;

			hw_mod_qsl_qen_get(&ndev->be, HW_QSL_QEN_EN,
					   queue_id / 4, &qen_value);
			hw_mod_qsl_qen_set(&ndev->be, HW_QSL_QEN_EN,
					   queue_id / 4,
					   qen_value | (1 << (queue_id % 4)));
			hw_mod_qsl_qen_flush(&ndev->be, queue_id / 4, 1);
		}
	}

	*rss_target_id = eth_dev->rss_target_id;

#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev,
				       FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

	nic_insert_eth_port_dev(ndev, eth_dev);

	pthread_mutex_unlock(&ndev->mtx);
	pthread_mutex_unlock(&base_mtx);
	return eth_dev;

err_exit0:
	pthread_mutex_unlock(&ndev->mtx);
	pthread_mutex_unlock(&base_mtx);

err_exit1:
	if (eth_dev)
		free(eth_dev);

#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev,
				       FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

	NT_LOG(DBG, FILTER, "ERR in %s\n", __func__);
	return NULL; /* Error exit */
}

int flow_eth_dev_add_queue(struct flow_eth_dev *eth_dev,
			   struct flow_queue_id_s *queue_id)
{
	uint32_t qen_value = 0;

	eth_dev->rx_queue[eth_dev->num_queues].id = queue_id->id;
	eth_dev->rx_queue[eth_dev->num_queues].hw_id = queue_id->hw_id;
	eth_dev->num_queues += 1;

	hw_mod_qsl_qen_get(&eth_dev->ndev->be, HW_QSL_QEN_EN,
			   queue_id->hw_id / 4, &qen_value);
	hw_mod_qsl_qen_set(&eth_dev->ndev->be, HW_QSL_QEN_EN,
			   queue_id->hw_id / 4,
			   qen_value | (1 << (queue_id->hw_id % 4)));
	hw_mod_qsl_qen_flush(&eth_dev->ndev->be, queue_id->hw_id / 4, 1);

	return 0;
}

int flow_delete_eth_dev(struct flow_eth_dev *eth_dev)
{
	struct flow_nic_dev *ndev = eth_dev->ndev;

	if (!ndev) {
		/* Error invalid nic device */
		return -1;
	}

	NT_LOG(DBG, FILTER, "Delete eth-port device %p, port %i\n", eth_dev,
	       eth_dev->port);

#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev,
				       FLOW_BACKEND_DEBUG_MODE_WRITE);
#endif

	/* delete all created flows from this device */
	pthread_mutex_lock(&ndev->mtx);

	struct flow_handle *flow = ndev->flow_base;

	while (flow) {
		if (flow->dev == eth_dev) {
			struct flow_handle *flow_next = flow->next;

			if (ndev->flow_profile ==
					FLOW_ETH_DEV_PROFILE_VSWITCH) {
				NT_LOG(ERR, FILTER, "vSwitch profile not supported");
				return -1;
			}
			flow_destroy_locked_profile_inline(eth_dev,
							   flow, NULL);
			flow = flow_next;
		} else {
			flow = flow->next;
		}
	}

	/*
	 * remove unmatched queue if setup in QSL
	 * remove exception queue setting in QSL UNM
	 */
	hw_mod_qsl_unmq_set(&ndev->be, HW_QSL_UNMQ_DEST_QUEUE, eth_dev->port,
			    0);
	hw_mod_qsl_unmq_set(&ndev->be, HW_QSL_UNMQ_EN, eth_dev->port, 0);
	hw_mod_qsl_unmq_flush(&ndev->be, eth_dev->port, 1);

	if (ndev->flow_profile == FLOW_ETH_DEV_PROFILE_INLINE) {
		for (int i = 0; i < eth_dev->num_queues; ++i) {
			uint32_t qen_value = 0;
			uint32_t queue_id =
				(uint32_t)eth_dev->rx_queue[i].hw_id;

			hw_mod_qsl_qen_get(&ndev->be, HW_QSL_QEN_EN,
					   queue_id / 4, &qen_value);
			hw_mod_qsl_qen_set(&ndev->be, HW_QSL_QEN_EN,
					   queue_id / 4,
					   qen_value & ~(1U << (queue_id % 4)));
			hw_mod_qsl_qen_flush(&ndev->be, queue_id / 4, 1);
		}
	}

#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev,
				       FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

#ifndef SCATTER_GATHER
	/* free rx queues */
	for (int i = 0; i < eth_dev->num_queues; i++) {
		ndev->be.iface->free_rx_queue(ndev->be.be_dev,
					      eth_dev->rx_queue[i].hw_id);
		flow_nic_deref_resource(ndev, RES_QUEUE,
					eth_dev->rx_queue[i].id);
	}
#endif

	/* take eth_dev out of ndev list */
	if (nic_remove_eth_port_dev(ndev, eth_dev) != 0)
		NT_LOG(ERR, FILTER, "ERROR : eth_dev %p not found\n", eth_dev);

	pthread_mutex_unlock(&ndev->mtx);

	/* free eth_dev */
	free(eth_dev);
	return 0;
}

int flow_get_tunnel_definition(struct tunnel_cfg_s *tun, uint32_t flow_stat_id,
			       uint8_t vport)
{
	return tunnel_get_definition(tun, flow_stat_id, vport);
}

/*
 * *****************************  Flow API NIC Setup  ***************************************
 * Flow backend creation function - register and initialize common backend API to FPA modules
 * ******************************************************************************************
 */

static int init_resource_elements(struct flow_nic_dev *ndev,
				  enum res_type_e res_type, uint32_t count)
{
	assert(ndev->res[res_type].alloc_bm == NULL);
	/* allocate bitmap and ref counter */
	ndev->res[res_type].alloc_bm =
		calloc(1, BIT_CONTAINER_8_ALIGN(count) + count * sizeof(uint32_t));
	if (ndev->res[res_type].alloc_bm) {
		ndev->res[res_type].ref =
			(uint32_t *)&ndev->res[res_type]
			.alloc_bm[BIT_CONTAINER_8_ALIGN(count)];
		ndev->res[res_type].resource_count = count;
		return 0;
	}
	return -1;
}

static void done_resource_elements(struct flow_nic_dev *ndev,
				   enum res_type_e res_type)
{
	assert(ndev);
	if (ndev->res[res_type].alloc_bm)
		free(ndev->res[res_type].alloc_bm);
}

static void list_insert_flow_nic(struct flow_nic_dev *ndev)
{
	pthread_mutex_lock(&base_mtx);
	ndev->next = dev_base;
	dev_base = ndev;
	pthread_mutex_unlock(&base_mtx);
}

static int list_remove_flow_nic(struct flow_nic_dev *ndev)
{
	pthread_mutex_lock(&base_mtx);
	struct flow_nic_dev *nic_dev = dev_base, *prev = NULL;

	while (nic_dev) {
		if (nic_dev == ndev) {
			if (prev)
				prev->next = nic_dev->next;
			else
				dev_base = nic_dev->next;
			pthread_mutex_unlock(&base_mtx);
			return 0;
		}
		prev = nic_dev;
		nic_dev = nic_dev->next;
	}

	pthread_mutex_unlock(&base_mtx);
	return -1;
}

struct flow_nic_dev *flow_api_create(uint8_t adapter_no,
				     const struct flow_api_backend_ops *be_if,
				     void *be_dev)
{
	if (!be_if || be_if->version != 1) {
		NT_LOG(DBG, FILTER, "ERR: %s\n", __func__);
		return NULL;
	}

	struct flow_nic_dev *ndev = calloc(1, sizeof(struct flow_nic_dev));

	if (!ndev) {
		NT_LOG(ERR, FILTER, "ERROR: calloc failed\n");
		return NULL;
	}

	/*
	 * To dump module initialization writes use
	 * FLOW_BACKEND_DEBUG_MODE_WRITE
	 * then remember to set it ...NONE afterwards again
	 */
	be_if->set_debug_mode(be_dev, FLOW_BACKEND_DEBUG_MODE_NONE);

	if (flow_api_backend_init(&ndev->be, be_if, be_dev) != 0)
		goto err_exit;
	ndev->adapter_no = adapter_no;

	ndev->ports = (uint16_t)((ndev->be.num_rx_ports > 256) ?
				 256 :
				 ndev->be.num_rx_ports);

	/*
	 * Free resources in NIC must be managed by this module
	 * Get resource sizes and create resource manager elements
	 */
	if (init_resource_elements(ndev, RES_QUEUE, ndev->be.max_queues))
		goto err_exit;
	if (init_resource_elements(ndev, RES_CAT_CFN,
				   ndev->be.cat.nb_cat_funcs))
		goto err_exit;
	if (init_resource_elements(ndev, RES_CAT_COT, ndev->be.max_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_CAT_EXO, ndev->be.cat.nb_pm_ext))
		goto err_exit;
	if (init_resource_elements(ndev, RES_CAT_LEN, ndev->be.cat.nb_len))
		goto err_exit;
	if (init_resource_elements(ndev, RES_KM_FLOW_TYPE,
				   ndev->be.cat.nb_flow_types))
		goto err_exit;
	if (init_resource_elements(ndev, RES_KM_CATEGORY,
				   ndev->be.km.nb_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_HSH_RCP, ndev->be.hsh.nb_rcp))
		goto err_exit;
	if (init_resource_elements(ndev, RES_PDB_RCP,
				   ndev->be.pdb.nb_pdb_rcp_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_QSL_RCP,
				   ndev->be.qsl.nb_rcp_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_QSL_QST,
				   ndev->be.qsl.nb_qst_entries))
		goto err_exit;
	if (init_resource_elements(ndev, RES_SLC_RCP, ndev->be.max_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_IOA_RCP,
				   ndev->be.ioa.nb_rcp_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_ROA_RCP,
				   ndev->be.roa.nb_tun_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_FLM_FLOW_TYPE,
				   ndev->be.cat.nb_flow_types))
		goto err_exit;
	if (init_resource_elements(ndev, RES_FLM_RCP,
				   ndev->be.flm.nb_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_HST_RCP,
				   ndev->be.hst.nb_hst_rcp_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_TPE_RCP,
				   ndev->be.tpe.nb_rcp_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_TPE_EXT,
				   ndev->be.tpe.nb_rpl_ext_categories))
		goto err_exit;
	if (init_resource_elements(ndev, RES_TPE_RPL,
				   ndev->be.tpe.nb_rpl_depth))
		goto err_exit;

	/* may need IPF, COR */

	/* check all defined has been initialized */
	for (int i = 0; i < RES_COUNT; i++)
		assert(ndev->res[i].alloc_bm);

	pthread_mutex_init(&ndev->mtx, NULL);
	list_insert_flow_nic(ndev);

	return ndev;

err_exit:
	if (ndev)
		flow_api_done(ndev);
	NT_LOG(DBG, FILTER, "ERR: %s\n", __func__);
	return NULL;
}

int flow_api_done(struct flow_nic_dev *ndev)
{
	NT_LOG(DBG, FILTER, "FLOW API DONE\n");
	if (ndev) {
		flow_ndev_reset(ndev);

		/* delete resource management allocations for this ndev */
		for (int i = 0; i < RES_COUNT; i++)
			done_resource_elements(ndev, i);

		flow_api_backend_done(&ndev->be);
		list_remove_flow_nic(ndev);
		free(ndev);
	}
	return 0;
}

void *flow_api_get_be_dev(struct flow_nic_dev *ndev)
{
	if (!ndev) {
		NT_LOG(DBG, FILTER, "ERR: %s\n", __func__);
		return NULL;
	}
	return ndev->be.be_dev;
}

int flow_get_num_queues(uint8_t adapter_no, uint8_t port_no)
{
	struct flow_eth_dev *eth_dev =
		nic_and_port_to_eth_dev(adapter_no, port_no);
	return eth_dev->num_queues;
}

int flow_get_hw_id(uint8_t adapter_no, uint8_t port_no, uint8_t queue_no)
{
	struct flow_eth_dev *eth_dev =
		nic_and_port_to_eth_dev(adapter_no, port_no);
	return eth_dev->rx_queue[queue_no].hw_id;
}

int flow_get_flm_stats(struct flow_nic_dev *ndev, uint64_t *data, uint64_t size)
{
	if (ndev->flow_profile == FLOW_ETH_DEV_PROFILE_INLINE)
		return flow_get_flm_stats_profile_inline(ndev, data, size);
	return -1;
}

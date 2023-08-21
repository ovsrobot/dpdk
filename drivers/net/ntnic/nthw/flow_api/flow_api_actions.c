/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h> /* htons, htonl, ntohs */

#include "ntlog.h"

#include "stream_binary_flow_api.h"
#include "flow_api_actions.h"
#include "flow_api_backend.h"
#include "flow_api_engine.h"

int flow_actions_create_roa_tunhdr(struct flow_api_backend_s *be, int index,
				   struct tunnel_header_s *tun)
{
	int err = 0;
	int num_writes = (tun->ip_version == 4) ? 4 : 8;

	/*
	 * Write 4 * 4 words = 64 bytes (IPv4) or 8 * 4 words = 128 bytes (IPv6)
	 */
	for (int i = 0; (i < num_writes) && !err; i++) {
		for (int ii = 0; (ii < 4) && !err; ii++) {
			/* must write each 4 words backwards! */
			err |= hw_mod_roa_tunhdr_set(be, HW_ROA_TUNHDR,
						     index, i * 4 + ii,
						     ntohl(tun->d.hdr32[(i + 1) * 4 - ii - 1]));
		}
	}

	return err;
}

int flow_actions_create_roa_tuncfg(struct flow_api_backend_s *be, int index,
				   uint64_t color_actions)
{
	hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_PRESET_ALL, index, 0);
	/*
	 * If tunnel header specified
	 */
	int tun_len = get_roa_tunhdr_len(color_actions);

	if (tun_len) {
		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_TUN_LEN, index,
				      tun_len);
		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_TUN_TYPE, index,
				      roa_get_tun_type(color_actions));

		/* set the total tunnel IP header length */
		if (get_roa_tun_ip_type(color_actions) == 1) {
			/* IPv6 */
			if ((size_t)tun_len > (sizeof(struct flow_elem_eth) +
					       sizeof(struct flow_elem_ipv6))) {
				hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPTL_UPD, index, 1);
				/* tunnel header length excludes the IPv6 header itself */
				hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPTL_PRECALC, index,
					(uint32_t)(tun_len -
						   (sizeof(struct flow_elem_eth) +
						    sizeof(struct flow_elem_ipv6))));
			}
		} else {
			/* IPv4 */
			if ((size_t)tun_len > sizeof(struct flow_elem_eth)) {
				hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPTL_UPD,
						      index, 1);
				hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPTL_PRECALC, index,
					(uint32_t)(tun_len -
						   sizeof(struct flow_elem_eth)));
			}
		}

		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IP_TYPE, index,
				      get_roa_tun_ip_type(color_actions));

		if (get_roa_tun_ip_type(color_actions) == 1) {
			/* IPv6 - Do not update the IP checksum in the tunnel header */
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPCS_UPD, index,
					      0);
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPCS_PRECALC,
					      index, 0);
		} else {
			/* IPv4 */
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPCS_UPD,
					      index, 1);
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_IPCS_PRECALC,
					      index,
					      get_roa_tun_ip_csum(color_actions));
		}

		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_VXLAN_UDP_LEN_UPD,
				      index, 1);

		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_PUSH_TUNNEL, index, 1);
	}

	/* bypass must be > 0 or recirculate_port >= 0 - bypass wins */
	uint8_t recirculate_bypass = roa_get_recirc_bypass_port(color_actions);

	if (recirculate_bypass) {
		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRC_BYPASS, index,
				      recirculate_bypass);
		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRCULATE, index, 1);

	} else {
		int32_t recirculate_port = roa_get_recirc_port(color_actions);

		hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRC_BYPASS, index,
				      255);

		if (recirculate_port >= 0) {
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRC_PORT,
					      index, recirculate_port);
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRCULATE,
					      index, 1);
		}
	}

	uint8_t tx = roa_get_tx(color_actions);

	if (tx) {
		if (tx == DESTINATION_TX_PHY0) {
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_TX_LAG_IX,
					      index, ROA_TX_PHY0);
		} else if (tx == DESTINATION_TX_PHY1) {
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_TX_LAG_IX,
					      index, ROA_TX_PHY1);
		} else if (tx == (DESTINATION_TX_PHY0 | DESTINATION_TX_PHY1)) {
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_TX_LAG_IX,
					      index, ROA_TX_PHY0);
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRC_BYPASS,
					      index, 0x81); /* port 1 - only port left */
			hw_mod_roa_tuncfg_set(be, HW_ROA_TUNCFG_RECIRCULATE,
					      index, 1);

		} else {
			return -1; /* ERR */
		}
	}

	/*
	 * Special IOA memory that contains ROA information - bad FPGA design
	 */
	if (tx || tun_len) {
		if (be->ioa.ver > 3 && tun_len &&
				get_roa_tun_ip_type(color_actions) == 1) {
			/* IPv6 VxLAN tunnel. Select EPP recipe 2 */
			hw_mod_ioa_roa_epp_set(be, HW_IOA_ROA_EPP_PUSH_TUNNEL,
					       index, 2);
		} else {
			/* IPv4 VxLAN tunnel or no tunnel (select recipe 1 or 0) */
			hw_mod_ioa_roa_epp_set(be, HW_IOA_ROA_EPP_PUSH_TUNNEL,
					       index, !!tun_len);
		}
		hw_mod_ioa_roa_epp_set(be, HW_IOA_ROA_EPP_TX_PORT, index, tx);
	}

	return 0;
}

int flow_actions_create_ioa_config(struct flow_api_backend_s *be, int index,
				   uint64_t color_actions)
{
	if (color_actions & ioa_set_vxlan_pop(0)) {
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_TUNNEL_POP, index, 1);
		NT_LOG(DBG, FILTER, "Pop outer Tunnel (Vxlan)\n");
	}

	if (color_actions & ioa_set_vlan_pop(0)) {
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_VLAN_POP, index, 1);
		NT_LOG(DBG, FILTER, "Pop outer Vlan\n");
	}

	int tpid_sel = ioa_get_tpid_sel(color_actions);

	if (color_actions & ioa_set_vlan_push(0, 0)) {
		uint16_t tci = ioa_get_vlan_tci(color_actions);

		NT_LOG(DBG, FILTER, "Push Vlan with TPID/TCI %04x/%04x\n",
		       tpid_sel ? 0x88a8 : 0x8100, tci);
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_VLAN_VID, index,
				   tci & 0x0FFF);
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_VLAN_DEI, index,
				   (tci >> 12) & 0x1);
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_VLAN_PCP, index,
				   (tci >> 13) & 0x7);
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_VLAN_PUSH, index, 1);
	}

	int queue = ioa_get_queue(color_actions);

	if (queue >= 0) {
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_QUEUE_OVERRIDE_EN, index, 1);
		hw_mod_ioa_rcp_set(be, HW_IOA_RCP_QUEUE_ID, index, queue);
	}

	hw_mod_ioa_rcp_set(be, HW_IOA_RCP_VLAN_TPID_SEL, index, tpid_sel);

	return 0;
}

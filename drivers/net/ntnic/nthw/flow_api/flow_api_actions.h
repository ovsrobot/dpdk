/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _FLOW_ACTIONS_H_
#define _FLOW_ACTIONS_H_

struct flow_api_backend_s;
struct tunnel_header_s;

#define MAX_COLOR_FLOW_STATS 0x400

#define ROA_RECIRC_BYPASS_PHY_OFFSET 0x80
#define MAX_REPLICATION_PORTS 2

enum {
	DESTINATION_TX_NONE = 0,
	DESTINATION_TX_PHY0 = 1,
	DESTINATION_TX_PHY1 = 2
};

enum { TUN_IPV4 = 0, TUN_IPV6 };

enum {
	VLAN_TPID_802_1Q = 0,
	VLAN_TPID_802_1AD,
	VLAN_TPID_CUSTOM_0,
	VLAN_TPID_CUSTOM_1
};

enum { ROA_TX_NO_RETRANSMIT = 0, ROA_TX_PHY0, ROA_TX_PHY1, ROA_TX_RESERVED };

/*
 * before version 6 of QSL
 */
#if (MAX_COLOR_FLOW_STATS == 0x4000)
#define MAX_HW_FLOW_STATS_OLD 0x3fff

#else
#if (MAX_COLOR_FLOW_STATS == 0x400)
#define MAX_HW_FLOW_STATS_OLD 0x03ff
#else
#error *** Unsupported number of color statistics counter ***
#endif
#endif

/*
 * OLD behavior substituted from 4.1+
 *
 * 13:0   Mark (color) 16384 flow stats
 * 21:14  IOA index      256 entries
 * 29:22  ROA index      256 entries
 * 31:30  1 to indicate this layout
 * or
 *  9:0   Mark (color) 1024 flow stats
 * 19:10  IOA index    1024 entries
 * 29:20  ROA index    1024 entries
 * 31:30  0 to indicate this layout
 */
static inline uint32_t set_color_action_old(uint32_t color, uint32_t ioa_rcp,
		uint32_t roa_rcp)
{
#if (MAX_COLOR_FLOW_STATS == 0x400)
	uint32_t color_action = (color & MAX_HW_FLOW_STATS_OLD) |
				((ioa_rcp & 0x3ff) << 10) |
				((roa_rcp & 0x3ff) << 20) | (0 << 30);
#else
	uint32_t color_action = (color & MAX_HW_FLOW_STATS_OLD) |
				((ioa_rcp & 0xff) << 14) |
				((roa_rcp & 0xff) << 22) | (1 << 30);
#endif
	return color_action;
}

#define BITMASK(a, b) ((1U << ((a) - (b) + 1)) - 1)

/*
 *  9:0   Mark (color) 1024 flow stats
 * 17:10  IOA index     256 entries
 * 25:18  ROA index     256 entries
 * 30:26  QSL and HSH    32 recipes indexable
 * 31:31  CAO               implicitly when color_action is set
 */
#define FLOW_MARK_MASK BITMASK(9, 0)
#define IOA_RCP_MASK BITMASK(17, 10)
#define ROA_RCP_MASK BITMASK(25, 18)
#define QSL_HSH_MASK BITMASK(30, 26)

static inline uint32_t set_color_action(uint32_t mark, uint32_t ioa_rcp,
					uint32_t roa_rcp, uint32_t qsl_hsh)
{
	uint32_t color_action = (mark & FLOW_MARK_MASK) |
				((ioa_rcp & IOA_RCP_MASK) << 10) |
				((roa_rcp & ROA_RCP_MASK) << 18) |
				((qsl_hsh & QSL_HSH_MASK) << 26) | (1 << 31);
	return color_action;
}

/*
 *  This is a bitmask representation in SW for
 *  roa config settings. It is mostly done for
 *  effective cache matching
 *
 *  ROA config  bit offs  bits
 *  ----------------------------
 *  recirc port      7:0    8   -> uses hbx > 0
 *  recirc bypass   15:8    8   -> uses hbx > 0  if set, will override
 *  tunnel type     19:16   4
 *  tx port         23:20   4   -> txport + 1
 *  tun_ip_type     24:24   1
 *  recirculate     25:25   1   -> recirculate port set
 *  tunhdr_len      33:26   8   -> tunnel header length - 0 if none
 *  ip_csum_prec    49:34  16   -> tunnel ip header checksum pre-calculated
 *  new_recirc_port 50:50   1   -> indication of a new port for recirculate has been allocated.
 *                                 Needs default queue
 */

static inline uint64_t set_roa_new_recirc_port(uint64_t actions)
{
	actions |= 1ULL << 50;
	return actions;
}

static inline uint8_t get_roa_new_recirc_port(uint64_t actions)
{
	return (uint8_t)((actions >> 50) & 1);
}

static inline uint64_t set_roa_tun_ip_type(uint64_t actions, uint8_t ip_type)
{
	actions |= (uint64_t)(ip_type & 1) << 24;
	return actions;
}

static inline uint8_t get_roa_tun_ip_type(uint64_t actions)
{
	return (uint8_t)((actions >> 24) & 1);
}

static inline uint64_t set_roa_tun_ip_csum(uint64_t actions, uint16_t csum)
{
	actions |= (uint64_t)csum << 34;
	return actions;
}

static inline uint16_t get_roa_tun_ip_csum(uint64_t actions)
{
	return (uint16_t)((actions >> 34) & 0xffff);
}

static inline uint64_t set_roa_tunhdr_len(uint64_t actions, uint8_t length)
{
	actions |= (uint64_t)length << 26;
	return actions;
}

static inline uint8_t get_roa_tunhdr_len(uint64_t actions)
{
	return (uint8_t)((actions >> 26) & 0xff);
}

static inline uint64_t set_roa_tx(uint64_t actions, uint8_t txport)
{
	actions |= ((txport + ROA_TX_PHY0) & 0x0f) << 20;
	return actions;
}

static inline uint8_t roa_get_tx(uint64_t actions)
{
	return (actions >> 20) & 0x0f;
}

static inline uint64_t set_roa_tun_type(uint64_t actions, uint8_t type)
{
	actions |= (type & 0x0f) << 16;
	return actions;
}

static inline uint8_t roa_get_tun_type(uint64_t actions)
{
	return (actions >> 16) & 0x0f;
}

static inline uint64_t set_roa_recirculate(uint64_t actions, uint8_t port)
{
	actions |= (1ULL << 25) | port;
	return actions;
}

static inline int32_t roa_get_recirc_port(uint64_t actions)
{
	if (!((1ULL << 25) & actions))
		return -1;
	return (actions & 0xff);
}

static inline uint64_t set_roa_recirc_bypass(uint64_t actions, uint8_t port)
{
	actions |= ((uint64_t)port & 0xff) << 8;
	return actions;
}

static inline uint8_t roa_get_recirc_bypass_port(uint64_t actions)
{
	return ((actions >> 8) & 0xff);
}

/*
 *  This is a bitmask representation in SW for
 *  ioa action settings. It is mostly done for
 *  effective cache matching
 *
 *  IOA action    bit offs    bits
 *  --------------------------------
 *  tci         15:0    16
 *  queue     23:16   8  uses hbx
 *  tpid select   27:24   4
 *  pop vxlan    28     1
 *  pop vlan     29     1
 *  push vlan    30     1
 *  queue override   31     1
 */

static inline uint64_t ioa_set_queue(uint64_t actions, uint8_t hb)
{
	actions |= (1 << 31) | ((uint64_t)hb << 16);
	return actions;
}

static inline int ioa_get_queue(uint64_t actions)
{
	if (!(actions & (1 << 31)))
		return -1;
	return ((actions >> 16) & 0xff);
}

static inline uint64_t ioa_set_vxlan_pop(uint64_t actions)
{
	actions |= 1 << 28;
	return actions;
}

static inline uint64_t ioa_set_vlan_pop(uint64_t actions)
{
	actions |= 1 << 29;
	return actions;
}

static inline uint64_t ioa_set_vlan_push_qinq(uint64_t actions)
{
	actions |= (VLAN_TPID_802_1AD & 0x0f) << 24;
	return actions;
}

static inline uint8_t ioa_get_tpid_sel(uint64_t actions)
{
	return (uint8_t)((actions >> 24) & 0x0f);
}

static inline uint64_t ioa_set_vlan_push(uint64_t actions, uint16_t tci)
{
	actions |= (1 << 30) | tci;
	return actions;
}

static inline uint64_t ioa_set_vlan_pcp(uint64_t actions, uint8_t pcp)
{
	actions |= (1 << 30) | ((uint16_t)(pcp & 7) << 13);
	return actions;
}

static inline uint16_t ioa_get_vlan_tci(uint64_t actions)
{
	return (uint16_t)(actions & 0xffff);
}

int flow_actions_create_roa_tunhdr(struct flow_api_backend_s *be, int index,
				   struct tunnel_header_s *tun);
int flow_actions_create_roa_tuncfg(struct flow_api_backend_s *be, int index,
				   uint64_t color_actions);
int flow_actions_create_ioa_config(struct flow_api_backend_s *be, int index,
				   uint64_t color_actions);

#endif /* _FLOW_ACTIONS_H_ */

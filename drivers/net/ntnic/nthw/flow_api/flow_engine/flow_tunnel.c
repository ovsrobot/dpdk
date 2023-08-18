/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h> /* htons, htonl, ntohs */
#include <stdio.h>
#include "stream_binary_flow_api.h"

#include "flow_api_backend.h"
#include "flow_api_engine.h"

#define MAX_HW_VIRT_PORTS 127 /* 255 reserved */
#define VIRTUAL_TUNNEL_PORT_OFFSET 72

struct tunnel_s {
	struct tunnel_cfg_s cfg;
	struct tunnel_cfg_s cfg_mask;
	uint32_t flow_stat_id;
	uint8_t vport;
	int refcnt;
	struct tunnel_s *next; /* linked list of defined tunnels */
};

int is_virtual_port(uint8_t virt_port)
{
	return !!(virt_port >= VIRTUAL_TUNNEL_PORT_OFFSET &&
		  virt_port < MAX_HW_VIRT_PORTS);
}

/*
 * New function for use with OVS 2.17.2
 */
static struct tunnel_s *tunnels;

static uint8_t vport[MAX_HW_VIRT_PORTS - VIRTUAL_TUNNEL_PORT_OFFSET + 1];

uint8_t flow_tunnel_alloc_virt_port(void)
{
	for (uint8_t i = VIRTUAL_TUNNEL_PORT_OFFSET; i < MAX_HW_VIRT_PORTS;
			i++) {
		if (!vport[i - VIRTUAL_TUNNEL_PORT_OFFSET]) {
			vport[i - VIRTUAL_TUNNEL_PORT_OFFSET] = 1;
			return i;
		}
	}

	/* no more virtual ports */
	return 255;
}

uint8_t flow_tunnel_free_virt_port(uint8_t virt_port)
{
	if (virt_port >= VIRTUAL_TUNNEL_PORT_OFFSET &&
			virt_port < MAX_HW_VIRT_PORTS) {
		vport[virt_port - VIRTUAL_TUNNEL_PORT_OFFSET] = 0;
		return 0;
	}
	return -1;
}

#define check(_v1, _v2, _msk1, _msk2) ({ \
	__typeof__(_v1) (v1) = (_v1); \
	__typeof__(_v2) (v2) = (_v2); \
	__typeof__(_msk1) (msk1) = (_msk1); \
	__typeof__(_msk2) (msk2) = (_msk2); \
	(((v1) & (msk1) & (msk2)) == ((v2) & (msk1) & (msk2))); \
})

#define check_tun_v4_equal(_tun_cfg, _tun_msk, _tun1_cfg, _tun1_msk) ({      \
	__typeof__(_tun_cfg) (tun_cfg) = (_tun_cfg); \
	__typeof__(_tun_msk) (tun_msk) = (_tun_msk); \
	__typeof__(_tun1_cfg) (tun1_cfg) = (_tun1_cfg); \
	__typeof__(_tun1_msk) (tun1_msk) = (_tun1_msk); \
	(check((tun_cfg)->v4.src_ip, (tun1_cfg)->v4.src_ip,              \
		(tun_msk)->v4.src_ip, (tun1_msk)->v4.src_ip) &&           \
	 check((tun_cfg)->v4.dst_ip, (tun1_cfg)->v4.dst_ip,              \
		(tun_msk)->v4.dst_ip, (tun1_msk)->v4.dst_ip) &&           \
	 check((tun_cfg)->s_port, (tun1_cfg)->s_port, (tun_msk)->s_port, \
		(tun1_msk)->s_port) &&                                    \
	 check((tun_cfg)->d_port, (tun1_cfg)->d_port, (tun_msk)->d_port, \
		(tun1_msk)->d_port)); \
})

#define check_tun_v6_equal(_tun_cfg, _tun_msk, _tun1_cfg, _tun1_msk) ({        \
	__typeof__(_tun_cfg) (tun_cfg) = (_tun_cfg); \
	__typeof__(_tun_msk) (tun_msk) = (_tun_msk); \
	__typeof__(_tun1_cfg) (tun1_cfg) = (_tun1_cfg); \
	__typeof__(_tun1_msk) (tun1_msk) = (_tun1_msk); \
	(check((tun_cfg)->v6_long.src_ip[0], (tun1_cfg)->v6_long.src_ip[0],    \
		(tun_msk)->v6_long.src_ip[0], (tun1_msk)->v6_long.src_ip[0]) && \
	 check((tun_cfg)->v6_long.src_ip[1], (tun1_cfg)->v6_long.src_ip[1],    \
		(tun_msk)->v6_long.src_ip[1], (tun1_msk)->v6_long.src_ip[1]) && \
	 check((tun_cfg)->v6_long.dst_ip[0], (tun1_cfg)->v6_long.dst_ip[0],    \
		(tun_msk)->v6_long.dst_ip[0], (tun1_msk)->v6_long.dst_ip[0]) && \
	 check((tun_cfg)->v6_long.dst_ip[1], (tun1_cfg)->v6_long.dst_ip[1],    \
		(tun_msk)->v6_long.dst_ip[1], (tun1_msk)->v6_long.dst_ip[1]) && \
	 check((tun_cfg)->s_port, (tun1_cfg)->s_port, (tun_msk)->s_port,       \
		(tun1_msk)->s_port) &&                                          \
	 check((tun_cfg)->d_port, (tun1_cfg)->d_port, (tun_msk)->d_port,       \
		(tun1_msk)->d_port)); \
})

static int check_tun_match(struct tunnel_s *tun,
			   const struct tunnel_cfg_s *tnlcfg,
			   const struct tunnel_cfg_s *tnlcfg_mask)
{
	if (tun->cfg.tun_type == tnlcfg->tun_type) {
		if (tun->cfg.ipversion == 4) {
			return check_tun_v4_equal(&tun->cfg, &tun->cfg_mask,
						  tnlcfg, tnlcfg_mask);
		} else {
			return check_tun_v6_equal(&tun->cfg, &tun->cfg_mask,
						  tnlcfg, tnlcfg_mask);
		}
	}
	return 0;
}

static struct tunnel_s *tunnel_get(const struct tunnel_cfg_s *tnlcfg,
				   const struct tunnel_cfg_s *tnlcfg_mask,
				   int tun_set)
{
	struct tunnel_s *tun = tunnels;

	while (tun) {
		if (tun->flow_stat_id != (uint32_t)-1) {
			/* This tun is already defined and set */
			if (tun_set) {
				/*
				 * A tunnel full match definition - search for duplicate
				 */
				if (memcmp(&tun->cfg, tnlcfg,
						sizeof(struct tunnel_cfg_s)) == 0 &&
						memcmp(&tun->cfg_mask, tnlcfg_mask,
						       sizeof(struct tunnel_cfg_s)) == 0)
					break;
			} else {
				/*
				 * A tunnel match search
				 */
				if (check_tun_match(tun, tnlcfg, tnlcfg_mask))
					break;
			}

		} else if (tun_set) {
			/*
			 * Check if this is a pre-configured tunnel for this one to be set
			 * try match them
			 */
			if (check_tun_match(tun, tnlcfg, tnlcfg_mask)) {
				/*
				 * Change the tun into the defining one - flow_stat_id is set later
				 */
				memcpy(&tun->cfg, tnlcfg,
				       sizeof(struct tunnel_cfg_s));
				memcpy(&tun->cfg_mask, tnlcfg_mask,
				       sizeof(struct tunnel_cfg_s));

				break;
			}

		} /* else ignore - both unset */
		tun = tun->next;
	}

	/*
	 * If not found, create and add it to db
	 */
	if (!tun) {
		uint8_t vport = flow_tunnel_alloc_virt_port();

		NT_LOG(DBG, FILTER, "Create NEW tunnel allocate vport %i\n",
		       vport);

		if (vport < 0xff) {
			tun = calloc(1, sizeof(struct tunnel_s));
			memcpy(&tun->cfg, tnlcfg, sizeof(struct tunnel_cfg_s));
			memcpy(&tun->cfg_mask, tnlcfg_mask,
			       sizeof(struct tunnel_cfg_s));

			/* flow_stat_id is set later from flow code */
			tun->flow_stat_id = (uint32_t)-1;
			tun->vport = vport;
			tun->refcnt = 1;

			tun->next = tunnels;
			tunnels = tun;
		}
	} else {
		tun->refcnt++;
		NT_LOG(DBG, FILTER, "Found tunnel has vport %i - ref %i\n",
		       tun->vport, tun->refcnt);
	}

	return tun;
}

int tunnel_release(struct tunnel_s *tnl)
{
	struct tunnel_s *tun = tunnels, *prev = NULL;

	NT_LOG(DBG, FILTER, "release tunnel vport %i, ref cnt %i..\n",
	       tnl->vport, tnl->refcnt);
	/* find tunnel in list */
	while (tun) {
		if (tun == tnl)
			break;
		prev = tun;
		tun = tun->next;
	}

	if (!tun) {
		NT_LOG(DBG, FILTER,
		       "ERROR: Tunnel not found in tunnel release!\n");
		return -1;
	}

	/* if last ref, take out of list */
	if (--tun->refcnt == 0) {
		if (prev)
			prev->next = tun->next;
		else
			tunnels = tun->next;
		flow_tunnel_free_virt_port(tun->vport);

		NT_LOG(DBG, FILTER,
		       "tunnel ref count == 0 remove tunnel vport %i\n",
		       tun->vport);
		free(tun);
	}

	return 0;
}

struct tunnel_s *tunnel_parse(const struct flow_elem *elem, int *idx,
			      uint32_t *vni)
{
	int eidx = *idx;
	struct tunnel_cfg_s tnlcfg;
	struct tunnel_cfg_s tnlcfg_mask;
	struct tunnel_s *rtnl = NULL;

	if (elem) {
		eidx++;
		memset(&tnlcfg, 0, sizeof(struct tunnel_cfg_s));
		int valid = 1;
		enum flow_elem_type last_type = FLOW_ELEM_TYPE_END;

		tnlcfg.d_port = 0xffff;
		tnlcfg.tun_type = -1;

		if (vni)
			*vni = (uint32_t)-1;

		while (elem[eidx].type != FLOW_ELEM_TYPE_END &&
				elem[eidx].type >= last_type && valid) {
			switch (elem[eidx].type) {
			case FLOW_ELEM_TYPE_ANY:
			case FLOW_ELEM_TYPE_ETH:
				/* Ignore */
				break;
			case FLOW_ELEM_TYPE_IPV4: {
				const struct flow_elem_ipv4 *ipv4 =
					(const struct flow_elem_ipv4 *)elem[eidx]
					.spec;
				const struct flow_elem_ipv4 *ipv4_mask =
					(const struct flow_elem_ipv4 *)elem[eidx]
					.mask;

				tnlcfg.v4.src_ip = ipv4->hdr.src_ip;
				tnlcfg.v4.dst_ip = ipv4->hdr.dst_ip;
				tnlcfg_mask.v4.src_ip = ipv4_mask->hdr.src_ip;
				tnlcfg_mask.v4.dst_ip = ipv4_mask->hdr.dst_ip;

				tnlcfg.ipversion = 4;
			}
			break;
			case FLOW_ELEM_TYPE_IPV6: {
				const struct flow_elem_ipv6 *ipv6 =
					(const struct flow_elem_ipv6 *)elem[eidx]
					.spec;
				const struct flow_elem_ipv6 *ipv6_mask =
					(const struct flow_elem_ipv6 *)elem[eidx]
					.mask;

				memcpy(tnlcfg.v6.src_ip, ipv6->hdr.src_addr,
				       sizeof(tnlcfg.v6.src_ip));
				memcpy(tnlcfg.v6.dst_ip, ipv6->hdr.dst_addr,
				       sizeof(tnlcfg.v6.dst_ip));
				memcpy(tnlcfg_mask.v6.src_ip,
				       ipv6_mask->hdr.src_addr,
				       sizeof(tnlcfg.v6.src_ip));
				memcpy(tnlcfg_mask.v6.dst_ip,
				       ipv6_mask->hdr.dst_addr,
				       sizeof(tnlcfg.v6.dst_ip));

				tnlcfg.ipversion = 6;
			}
			break;

			case FLOW_ELEM_TYPE_UDP: {
				const struct flow_elem_udp *udp =
					(const struct flow_elem_udp *)elem[eidx]
					.spec;
				const struct flow_elem_udp *udp_mask =
					(const struct flow_elem_udp *)elem[eidx]
					.mask;

				tnlcfg.s_port = udp->hdr.src_port;
				tnlcfg.d_port = udp->hdr.dst_port;
				tnlcfg_mask.s_port = udp_mask->hdr.src_port;
				tnlcfg_mask.d_port = udp_mask->hdr.dst_port;
			}
			break;

			case FLOW_ELEM_TYPE_VXLAN: {
				const struct flow_elem_vxlan *vxlan =
					(const struct flow_elem_vxlan *)
					elem[eidx]
					.spec;
				if (vni)
					*vni = (uint32_t)(((uint32_t)
							   vxlan->vni[0]
							   << 16) |
							  ((uint32_t)
							   vxlan->vni[1]
							   << 8) |
							  ((uint32_t)vxlan
							   ->vni[2]));

				tnlcfg.tun_type = FLOW_ELEM_TYPE_VXLAN;
			}
			break;
			default:
				valid = 0;
				break;
			}

			last_type = elem[eidx].type;
			eidx++;
		}

		/*
		 * vxlan ports : 4789 or 8472
		 */
		if (tnlcfg.tun_type < 0 &&
				(tnlcfg.d_port == 0xb512 || tnlcfg.d_port == 0x1821))
			tnlcfg.tun_type = FLOW_ELEM_TYPE_VXLAN;

		if (!valid || tnlcfg.ipversion == 0 || tnlcfg.tun_type < 0 ||
				tnlcfg.d_port == 0xffff) {
			NT_LOG(DBG, FILTER, "Invalid tunnel received\n");
			return NULL;
		}

		/* search/add to DB */
		rtnl = tunnel_get(&tnlcfg, &tnlcfg_mask,
				  vni ? 0 :
				  1); /* if vni == NULL it is a tun set command */

#ifdef FLOW_DEBUG
		if (rtnl) {
			if (vni)
				NT_LOG(DBG, FILTER,
				       "MATCH A TUNNEL DEFINITION - PRESET "
				       "(PREALLOC VPORT) IF NOT FOUND:\n");
			else
				NT_LOG(DBG, FILTER,
				       "SET A TUNNEL DEFINITION:\n");
			struct in_addr addr, mask;
			char buf[64];

			addr.s_addr = rtnl->cfg.v4.src_ip;
			sprintf(buf, "%s", inet_ntoa(addr));
			mask.s_addr = rtnl->cfg_mask.v4.src_ip;
			NT_LOG(DBG, FILTER, "    tun src IP: %s / %s\n", buf,
			       inet_ntoa(mask));
			addr.s_addr = rtnl->cfg.v4.dst_ip;
			sprintf(buf, "%s", inet_ntoa(addr));
			mask.s_addr = rtnl->cfg_mask.v4.dst_ip;
			NT_LOG(DBG, FILTER, "    tun dst IP: %s / %s\n", buf,
			       inet_ntoa(mask));
			NT_LOG(DBG, FILTER, "    tun tp_src: %i / %04x\n",
			       htons(rtnl->cfg.s_port),
			       htons(rtnl->cfg_mask.s_port));
			NT_LOG(DBG, FILTER, "    tun tp_dst: %i / %04x\n",
			       htons(rtnl->cfg.d_port),
			       htons(rtnl->cfg_mask.d_port));
			NT_LOG(DBG, FILTER, "    tun ipver:  %i\n",
			       rtnl->cfg.ipversion);
			NT_LOG(DBG, FILTER, "    tun flow_stat_id: %i\n",
			       rtnl->flow_stat_id);
			NT_LOG(DBG, FILTER, "    tun vport:  %i\n",
			       rtnl->vport);
			NT_LOG(DBG, FILTER, "    tun refcnt: %i\n",
			       rtnl->refcnt);
		}
#endif

		*idx = eidx; /* pointing to next or END */
	}

	return rtnl;
}

uint8_t get_tunnel_vport(struct tunnel_s *rtnl)
{
	return rtnl->vport;
}

void tunnel_set_flow_stat_id(struct tunnel_s *rtnl, uint32_t flow_stat_id)
{
	rtnl->flow_stat_id = flow_stat_id;
}

int tunnel_get_definition(struct tunnel_cfg_s *tuncfg, uint32_t flow_stat_id,
			  uint8_t vport)
{
	struct tunnel_s *tun = tunnels;

	while (tun) {
		if (tun->vport == vport && (flow_stat_id == tun->flow_stat_id ||
					    flow_stat_id == (uint32_t)-1)) {
			memcpy(tuncfg, &tun->cfg, sizeof(struct tunnel_cfg_s));
			return 0;
		}
		tun = tun->next;
	}

	return -1;
}

static be16_t ip_checksum_sum(const be16_t *data, unsigned int size,
			      be16_t seed)
{
	unsigned int sum = seed;
	unsigned int idx;

	for (idx = 0; idx < size / 2; idx++)
		sum += (unsigned int)(data[idx]);
	if (size & 1)
		sum += (unsigned char)data[idx];
	/* unfold */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (be16_t)sum;
}

static void copy_unmasked(uint8_t *result, const struct flow_elem *elem,
			  uint8_t size)
{
	for (uint8_t i = 0; i < size; i++)
		result[i] = ((const uint8_t *)elem->spec)[i];
}

int flow_tunnel_create_vxlan_hdr(struct flow_api_backend_s *be,
				 struct nic_flow_def *fd,
				 const struct flow_elem *elem)
{
	uint32_t eidx = 0;
	uint8_t size;
	struct ipv4_hdr_s *tun_ipv4 = NULL;
	uint16_t *tun_hdr_eth_type_p = NULL;

	if (elem) {
		while (elem[eidx].type != FLOW_ELEM_TYPE_END) {
			switch (elem[eidx].type) {
			case FLOW_ELEM_TYPE_ETH: {
				NT_LOG(DBG, FILTER,
				       "Tunnel: RTE_FLOW_ITEM_TYPE_ETH\n");
				struct flow_elem_eth eth;

				size = sizeof(struct flow_elem_eth);

				copy_unmasked((uint8_t *)&eth, &elem[eidx],
					      size);

				memcpy(&fd->tun_hdr.d.hdr8[fd->tun_hdr.len],
				       &eth, size);

				/*
				 * Save a pointer to the tun header ethtype field
				 * (needed later in the IPv4 and IPv6 flow elem cases)
				 */
				tun_hdr_eth_type_p =
					(uint16_t *)&fd->tun_hdr.d
					.hdr8[fd->tun_hdr.len + 12];

#ifdef FLOW_DEBUG
				NT_LOG(DBG, FILTER,
				       "dmac   : %02x:%02x:%02x:%02x:%02x:%02x\n",
				       eth.d_addr.addr_b[0],
				       eth.d_addr.addr_b[1],
				       eth.d_addr.addr_b[2],
				       eth.d_addr.addr_b[3],
				       eth.d_addr.addr_b[5],
				       eth.d_addr.addr_b[5]);
				NT_LOG(DBG, FILTER,
				       "smac   : %02x:%02x:%02x:%02x:%02x:%02x\n",
				       eth.s_addr.addr_b[0],
				       eth.s_addr.addr_b[1],
				       eth.s_addr.addr_b[2],
				       eth.s_addr.addr_b[3],
				       eth.s_addr.addr_b[5],
				       eth.s_addr.addr_b[5]);
				NT_LOG(DBG, FILTER, "type   : %04x\n",
				       ntohs(eth.ether_type));
#endif
				fd->tun_hdr.len =
					(uint8_t)(fd->tun_hdr.len + size);
			}
			break;
			/* VLAN is not supported */

			case FLOW_ELEM_TYPE_IPV4: {
				NT_LOG(DBG, FILTER,
				       "Tunnel:  RTE_FLOW_ITEM_TYPE_IPV4\n");
				struct flow_elem_ipv4 ipv4;

				size = sizeof(struct flow_elem_ipv4);

				copy_unmasked((uint8_t *)&ipv4, &elem[eidx],
					      size);

				if (ipv4.hdr.version_ihl != 0x45)
					ipv4.hdr.version_ihl = 0x45;

				if (ipv4.hdr.ttl == 0)
					ipv4.hdr.ttl = 64;

				if (ipv4.hdr.next_proto_id !=
						17)   /* must be UDP */
					ipv4.hdr.next_proto_id = 17;

				ipv4.hdr.frag_offset =
					htons(1 << 14); /* DF flag */

				size = sizeof(struct ipv4_hdr_s);
				memcpy(&fd->tun_hdr.d.hdr8[fd->tun_hdr.len],
				       &ipv4.hdr, size);

				/* Set the tun header ethtype field to IPv4 (if empty) */
				if (tun_hdr_eth_type_p &&
						(*tun_hdr_eth_type_p == 0)) {
					*tun_hdr_eth_type_p =
						htons(0x0800); /* IPv4 */
				}

				tun_ipv4 = (struct ipv4_hdr_s *)&fd->tun_hdr.d
					   .hdr8[fd->tun_hdr.len];

				NT_LOG(DBG, FILTER, "v_ihl  : %02x\n",
				       tun_ipv4->version_ihl);
				NT_LOG(DBG, FILTER, "tos    : %02x\n",
				       tun_ipv4->tos);
				NT_LOG(DBG, FILTER, "len    : %d\n",
				       ntohs(tun_ipv4->length));
				NT_LOG(DBG, FILTER, "id     : %02x\n",
				       tun_ipv4->id);
				NT_LOG(DBG, FILTER, "fl/frg : %04x\n",
				       ntohs(tun_ipv4->frag_offset));
				NT_LOG(DBG, FILTER, "ttl    : %02x\n",
				       tun_ipv4->ttl);
				NT_LOG(DBG, FILTER, "prot   : %02x\n",
				       tun_ipv4->next_proto_id);
				NT_LOG(DBG, FILTER, "chksum : %04x\n",
				       ntohs(tun_ipv4->hdr_csum));
				NT_LOG(DBG, FILTER, "src    : %d.%d.%d.%d\n",
				       (tun_ipv4->src_ip & 0xff),
				       ((tun_ipv4->src_ip >> 8) & 0xff),
				       ((tun_ipv4->src_ip >> 16) & 0xff),
				       ((tun_ipv4->src_ip >> 24) & 0xff));
				NT_LOG(DBG, FILTER, "dst    : %d.%d.%d.%d\n",
				       (tun_ipv4->dst_ip & 0xff),
				       ((tun_ipv4->dst_ip >> 8) & 0xff),
				       ((tun_ipv4->dst_ip >> 16) & 0xff),
				       ((tun_ipv4->dst_ip >> 24) & 0xff));

				fd->tun_hdr.len =
					(uint8_t)(fd->tun_hdr.len + size);
				fd->tun_hdr.ip_version = 4;
			}
			break;

			case FLOW_ELEM_TYPE_IPV6: {
				if (be->roa.ver < 6) {
					NT_LOG(ERR, FILTER,
					       "Tunnel flow element type IPv6 requires ROA version 6 or higher (current version=%d)\n",
					       be->roa.ver);
					return -1;
				}

				NT_LOG(DBG, FILTER,
				       "Tunnel:  RTE_FLOW_ITEM_TYPE_IPV6\n");
				struct flow_elem_ipv6 ipv6;

				size = sizeof(struct flow_elem_ipv6);

				copy_unmasked((uint8_t *)&ipv6, &elem[eidx],
					      size);

				/*
				 * Make sure the version field (the 4 most significant bits of
				 * "vtc_flow") is set to 6
				 */
				if ((ipv6.hdr.vtc_flow & htonl(0x60000000)) ==
						0) {
					ipv6.hdr.vtc_flow |= htonl(0x60000000); /* Version = 6 */
				}

				if (ipv6.hdr.proto != 17)   /* must be UDP */
					ipv6.hdr.proto = 17;

				if (ipv6.hdr.hop_limits == 0)
					ipv6.hdr.hop_limits = 64;

				size = sizeof(struct ipv6_hdr_s);
				memcpy(&fd->tun_hdr.d.hdr8[fd->tun_hdr.len],
				       &ipv6.hdr, size);

				/* Set the tun header ethtype field to IPv6 (if empty) */
				if (tun_hdr_eth_type_p &&
						(*tun_hdr_eth_type_p == 0)) {
					*tun_hdr_eth_type_p =
						htons(0x86DD); /* IPv6 */
				}

				NT_LOG(DBG, FILTER, "vtc_flow    : %08x\n",
				       ntohl(ipv6.hdr.vtc_flow));
				NT_LOG(DBG, FILTER, "payload_len : %04x\n",
				       ntohs(ipv6.hdr.payload_len));
				NT_LOG(DBG, FILTER, "proto       : %02x\n",
				       ipv6.hdr.proto);
				NT_LOG(DBG, FILTER, "hop_limits  : %02x\n",
				       ipv6.hdr.hop_limits);
				NT_LOG(DBG, FILTER,
				       "src         : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				       ipv6.hdr.src_addr[0],
				       ipv6.hdr.src_addr[1],
				       ipv6.hdr.src_addr[2],
				       ipv6.hdr.src_addr[3],
				       ipv6.hdr.src_addr[4],
				       ipv6.hdr.src_addr[5],
				       ipv6.hdr.src_addr[6],
				       ipv6.hdr.src_addr[7],
				       ipv6.hdr.src_addr[8],
				       ipv6.hdr.src_addr[9],
				       ipv6.hdr.src_addr[10],
				       ipv6.hdr.src_addr[11],
				       ipv6.hdr.src_addr[12],
				       ipv6.hdr.src_addr[13],
				       ipv6.hdr.src_addr[14],
				       ipv6.hdr.src_addr[15]);
				NT_LOG(DBG, FILTER,
				       "dst         : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				       ipv6.hdr.dst_addr[0],
				       ipv6.hdr.dst_addr[1],
				       ipv6.hdr.dst_addr[2],
				       ipv6.hdr.dst_addr[3],
				       ipv6.hdr.dst_addr[4],
				       ipv6.hdr.dst_addr[5],
				       ipv6.hdr.dst_addr[6],
				       ipv6.hdr.dst_addr[7],
				       ipv6.hdr.dst_addr[8],
				       ipv6.hdr.dst_addr[9],
				       ipv6.hdr.dst_addr[10],
				       ipv6.hdr.dst_addr[11],
				       ipv6.hdr.dst_addr[12],
				       ipv6.hdr.dst_addr[13],
				       ipv6.hdr.dst_addr[14],
				       ipv6.hdr.dst_addr[15]);

				fd->tun_hdr.len =
					(uint8_t)(fd->tun_hdr.len + size);
				fd->tun_hdr.ip_version = 6;
			}
			break;

			case FLOW_ELEM_TYPE_UDP: {
				NT_LOG(DBG, FILTER,
				       "Tunnel: RTE_FLOW_ITEM_TYPE_UDP\n");
				struct flow_elem_udp udp;

				size = sizeof(struct flow_elem_udp);

				copy_unmasked((uint8_t *)&udp, &elem[eidx],
					      size);

				udp.hdr.cksum =
					0; /* set always the UDP checksum to 0 */

				size = sizeof(struct udp_hdr_s);
				memcpy(&fd->tun_hdr.d.hdr8[fd->tun_hdr.len],
				       &udp.hdr, size);

				NT_LOG(DBG, FILTER, "src p  : %d\n",
				       ntohs(udp.hdr.src_port));
				NT_LOG(DBG, FILTER, "dst p  : %d\n",
				       ntohs(udp.hdr.dst_port));
				NT_LOG(DBG, FILTER, "len    : %d\n",
				       ntohs(udp.hdr.len));
				NT_LOG(DBG, FILTER, "chksum : %04x\n",
				       ntohs(udp.hdr.cksum));

				fd->tun_hdr.len =
					(uint8_t)(fd->tun_hdr.len + size);
			}
			break;

			case FLOW_ELEM_TYPE_VXLAN: {
				struct flow_elem_vxlan vxlan_m;

				size = sizeof(struct flow_elem_vxlan);

				copy_unmasked((uint8_t *)&vxlan_m, &elem[eidx],
					      size);

				vxlan_m.flags =
					0x08; /* set always I-flag - valid VNI */

				NT_LOG(DBG, FILTER,
				       "Tunnel: RTE_FLOW_ITEM_TYPE_VXLAN - vni %u\n",
				       (vxlan_m.vni[0] << 16) +
				       (vxlan_m.vni[1] << 8) +
				       vxlan_m.vni[2]);

				memcpy(&fd->tun_hdr.d.hdr8[fd->tun_hdr.len],
				       &vxlan_m, size);

				NT_LOG(DBG, FILTER, "flags  : %02x\n",
				       vxlan_m.flags);
				NT_LOG(DBG, FILTER, "vni    : %d\n",
				       (vxlan_m.vni[0] << 16) +
				       (vxlan_m.vni[1] << 8) +
				       vxlan_m.vni[2]);

				fd->tun_hdr.len =
					(uint8_t)(fd->tun_hdr.len + size);
			}
			break;

			case FLOW_ELEM_TYPE_PORT_ID: {
				const struct flow_elem_port_id *port =
					(const struct flow_elem_port_id *)
					elem[eidx]
					.spec;
				fd->tun_hdr.user_port_id = port->id;
			}
			break;

			case FLOW_ELEM_TYPE_VOID: {
				NT_LOG(DBG, FILTER,
				       "Tunnel: RTE_FLOW_ITEM_TYPE_VOID (ignoring)\n");
			}
			break;

			default:
				NT_LOG(INF, FILTER,
				       "unsupported Tunnel flow element type %u\n",
				       elem[eidx].type);
				return -1;
			}

			eidx++;
		}
	}

	if (tun_ipv4) {
		tun_ipv4->hdr_csum = 0;
		tun_ipv4->length = 0;
		fd->tun_hdr.ip_csum_precalc = ntohs(ip_checksum_sum((const be16_t *)&fd->tun_hdr.d
			.hdr8[14],
			(unsigned int)sizeof(struct ipv4_hdr_s),
			(be16_t)htons((uint16_t)(fd->tun_hdr.len - sizeof(struct flow_elem_eth)))));

		NT_LOG(DBG, FILTER,
		       "chksum precalc: %04x, precalc hdr len %u\n",
		       fd->tun_hdr.ip_csum_precalc,
		       fd->tun_hdr.len - sizeof(struct flow_elem_eth));
	}

	return 0;
}

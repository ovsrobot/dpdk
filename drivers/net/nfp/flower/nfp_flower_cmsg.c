/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#include "../nfpcore/nfp_nsp.h"
#include "../nfp_logs.h"
#include "../nfp_common.h"
#include "nfp_flower.h"
#include "nfp_flower_cmsg.h"
#include "nfp_flower_ctrl.h"
#include "nfp_flower_representor.h"

static void *
nfp_flower_cmsg_init(__rte_unused struct rte_mbuf *m,
		__rte_unused enum nfp_flower_cmsg_type type,
		__rte_unused uint32_t size)
{
	char *pkt;
	uint32_t data;
	uint32_t new_size = size;
	struct nfp_flower_cmsg_hdr *hdr;

	pkt = rte_pktmbuf_mtod(m, char *);
	PMD_DRV_LOG(DEBUG, "flower_cmsg_init using pkt at %p", pkt);

	data = rte_cpu_to_be_32(NFP_NET_META_PORTID);
	rte_memcpy(pkt, &data, 4);
	pkt += 4;
	new_size += 4;

	/* First the metadata as flower requires it */
	data = rte_cpu_to_be_32(NFP_META_PORT_ID_CTRL);
	rte_memcpy(pkt, &data, 4);
	pkt += 4;
	new_size += 4;

	/* Now the ctrl header */
	hdr = (struct nfp_flower_cmsg_hdr *)pkt;
	hdr->pad     = 0;
	hdr->type    = type;
	hdr->version = NFP_FLOWER_CMSG_VER1;

	pkt = (char *)hdr + NFP_FLOWER_CMSG_HLEN;
	new_size += NFP_FLOWER_CMSG_HLEN;

	m->pkt_len = new_size;
	m->data_len = m->pkt_len;

	return pkt;
}

static void
nfp_flower_cmsg_mac_repr_init(struct rte_mbuf *m, int num_ports)
{
	uint32_t size;
	struct nfp_flower_cmsg_mac_repr *msg;
	enum nfp_flower_cmsg_type type = NFP_FLOWER_CMSG_TYPE_MAC_REPR;

	size = sizeof(*msg) + (num_ports * sizeof(msg->ports[0]));
	PMD_INIT_LOG(DEBUG, "mac repr cmsg init with size: %u", size);
	msg = (struct nfp_flower_cmsg_mac_repr *)nfp_flower_cmsg_init(m,
			type, size);

	memset(msg->reserved, 0, sizeof(msg->reserved));
	msg->num_ports = num_ports;
}

static void
nfp_flower_cmsg_mac_repr_fill(struct rte_mbuf *m,
		unsigned int idx,
		unsigned int nbi,
		unsigned int nbi_port,
		unsigned int phys_port)
{
	struct nfp_flower_cmsg_mac_repr *msg;

	msg = (struct nfp_flower_cmsg_mac_repr *)nfp_flower_cmsg_get_data(m);
	msg->ports[idx].idx       = idx;
	msg->ports[idx].info      = nbi & NFP_FLOWER_CMSG_MAC_REPR_NBI;
	msg->ports[idx].nbi_port  = nbi_port;
	msg->ports[idx].phys_port = phys_port;
}

int
nfp_flower_cmsg_mac_repr(struct nfp_app_flower *app_flower)
{
	int i;
	unsigned int nbi;
	unsigned int nbi_port;
	unsigned int phys_port;
	struct rte_mbuf *mac_repr_cmsg;
	struct nfp_eth_table *nfp_eth_table;

	nfp_eth_table = app_flower->nfp_eth_table;

	mac_repr_cmsg = rte_pktmbuf_alloc(app_flower->ctrl_pktmbuf_pool);
	if (mac_repr_cmsg == NULL) {
		PMD_INIT_LOG(ERR, "Could not allocate mac repr cmsg");
		return -ENOMEM;
	}

	nfp_flower_cmsg_mac_repr_init(mac_repr_cmsg,
			app_flower->num_phyport_reprs);

	/* Fill in the mac repr cmsg */
	for (i = 0; i < app_flower->num_phyport_reprs; i++) {
		nbi = nfp_eth_table->ports[i].nbi;
		nbi_port = nfp_eth_table->ports[i].base;
		phys_port = nfp_eth_table->ports[i].index;

		nfp_flower_cmsg_mac_repr_fill(mac_repr_cmsg, i, nbi, nbi_port,
				phys_port);
	}

	/* Send the cmsg via the ctrl vNIC */
	return nfp_flower_ctrl_vnic_xmit(app_flower, mac_repr_cmsg);
}

int
nfp_flower_cmsg_repr_reify(struct nfp_app_flower *app_flower,
		struct nfp_flower_representor *repr)
{
	struct rte_mbuf *mbuf;
	struct nfp_flower_cmsg_port_reify *msg;

	mbuf = rte_pktmbuf_alloc(app_flower->ctrl_pktmbuf_pool);
	if (mbuf == NULL) {
		PMD_INIT_LOG(DEBUG, "alloc mbuf for repr reify failed");
		return -ENOMEM;
	}

	msg = (struct nfp_flower_cmsg_port_reify *)nfp_flower_cmsg_init(mbuf,
			NFP_FLOWER_CMSG_TYPE_PORT_REIFY, sizeof(*msg));

	msg->portnum  = rte_cpu_to_be_32(repr->port_id);
	msg->reserved = 0;
	msg->info     = rte_cpu_to_be_16(1);

	return nfp_flower_ctrl_vnic_xmit(app_flower, mbuf);
}

int
nfp_flower_cmsg_port_mod(struct nfp_app_flower *app_flower,
		uint32_t port_id, bool carrier_ok)
{
	struct nfp_flower_cmsg_port_mod *msg;
	struct rte_mbuf *mbuf;

	mbuf = rte_pktmbuf_alloc(app_flower->ctrl_pktmbuf_pool);
	if (mbuf == NULL) {
		PMD_INIT_LOG(DEBUG, "alloc mbuf for repr portmod failed");
		return -ENOMEM;
	}

	msg = (struct nfp_flower_cmsg_port_mod *)nfp_flower_cmsg_init(mbuf,
			NFP_FLOWER_CMSG_TYPE_PORT_MOD, sizeof(*msg));

	msg->portnum  = rte_cpu_to_be_32(port_id);
	msg->reserved = 0;
	msg->info     = carrier_ok;
	msg->mtu      = 9000;

	return nfp_flower_ctrl_vnic_xmit(app_flower, mbuf);
}

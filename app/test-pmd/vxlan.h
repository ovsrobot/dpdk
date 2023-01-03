#ifndef __VXLAN_H
#define __VXLAN_H
#include <rte_ether.h>



struct encap_vxlan_ipv4_vlan_data {
	struct rte_ether_hdr ether;
	struct rte_vlan_hdr vlan;
	struct rte_ipv4_hdr ipv4;
	struct rte_udp_hdr udp;
	struct rte_vxlan_hdr vxlan;
} __rte_packed __rte_aligned(2);

struct encap_vxlan_ipv4_data {
	struct rte_ether_hdr ether;
	struct rte_ipv4_hdr ipv4;
	struct rte_udp_hdr udp;
	struct rte_vxlan_hdr vxlan;
} __rte_packed __rte_aligned(2);


#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef _IN_H_
#define _IN_H_

#define IPPROTO_IP 0               /* Dummy for IP */
#define IPPROTO_HOPOPTS 0          /* IPv6 Hop-by-Hop options */
#define IPPROTO_IPIP 4             /* IPIP tunnels (for compatibility) */
#define IPPROTO_TCP 6              /* Transmission Control Protocol */
#define IPPROTO_UDP 17             /* User Datagram Protocol */
#define IPPROTO_IPV6 41            /* IPv6 header */
#define IPPROTO_ROUTING 43         /* IPv6 routing header */
#define IPPROTO_FRAGMENT 44        /* IPv6 fragmentation header */
#define IPPROTO_GRE 47             /* General Routing Encap */
#define IPPROTO_ESP 50             /* IPsec Encap Sec. Payload */
#define IPPROTO_AH 51              /* IPsec Auth Header */
#define IPPROTO_NONE 59            /* IPv6 no next header */
#define IPPROTO_DSTOPTS 60         /* IPv6 destination option */
#define IPPROTO_SCTP 132           /* Stream Control Transmission Protocol */

#endif

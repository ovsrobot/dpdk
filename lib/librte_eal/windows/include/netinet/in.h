/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef _IN_H_
#define _IN_H_

#define IPPROTO_IP 0
#define IPPROTO_HOPOPTS 0
#define	IPPROTO_IPV4 4             /* IPv4 encapsulation */
#define	IPPROTO_IPIP IPPROTO_IPV4  /* for compatibility */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define	IPPROTO_IPV6 41	           /* IP6 header */
#define	IPPROTO_ROUTING 43         /* IP6 routing header */
#define	IPPROTO_FRAGMENT 44        /* IP6 fragmentation header */
#define	IPPROTO_GRE 47             /* General Routing Encap. */
#define	IPPROTO_ESP 50             /* IP6 Encap Sec. Payload */
#define	IPPROTO_AH 51              /* IP6 Auth Header */
#define IPPROTO_NONE 59            /* IPv6 no next header */
#define	IPPROTO_DSTOPTS 60         /* IP6 destination option */
#define IPPROTO_SCTP 132           /* Stream Control Transmission Protocol */


#endif

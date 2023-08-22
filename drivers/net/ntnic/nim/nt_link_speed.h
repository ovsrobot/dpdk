/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NT_LINK_SPEED_H_
#define NT_LINK_SPEED_H_

#include <stdint.h>

/*
 * Link speed.
 * Note this is a bitmask.
 */
enum nt_link_speed_e {
	NT_LINK_SPEED_UNKNOWN = 0,
	NT_LINK_SPEED_10M = 0x01, /* 10 Mbps */
	NT_LINK_SPEED_100M = 0x02, /* 100 Mbps */
	NT_LINK_SPEED_1G = 0x04, /* 1 Gbps  (Autoneg only) */
	NT_LINK_SPEED_10G = 0x08, /* 10 Gbps (Autoneg only) */
	NT_LINK_SPEED_40G = 0x10, /* 40 Gbps (Autoneg only) */
	NT_LINK_SPEED_100G = 0x20, /* 100 Gbps (Autoneg only) */
	NT_LINK_SPEED_50G = 0x40, /* 50 Gbps (Autoneg only) */
	NT_LINK_SPEED_25G = 0x80, /* 25 Gbps (Autoneg only) */
	NT_LINK_SPEED_END /* always keep this entry as the last in enum */
};

typedef enum nt_link_speed_e nt_link_speed_t;

const char *nt_translate_link_speed(nt_link_speed_t link_speed);
const char *nt_translate_link_speed_mask(uint32_t link_speed_mask, char *buffer,
				      uint32_t length);
uint64_t nt_get_link_speed(nt_link_speed_t e_link_speed);

#endif /* NT_LINK_SPEED_H_ */

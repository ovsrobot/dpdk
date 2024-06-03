/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NT_LINK_SPEED_H_
#define NT_LINK_SPEED_H_

#include <stdint.h>
#include "nt4ga_link.h"

const char *nt_translate_link_speed(nt_link_speed_t link_speed);
uint64_t nt_get_link_speed(nt_link_speed_t e_link_speed);
uint64_t nt_get_max_link_speed(uint32_t link_speed_mask);

#endif	/* NT_LINK_SPEED_H_ */

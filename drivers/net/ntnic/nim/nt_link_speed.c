/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "nt_link_speed.h"
#include "nt4ga_link.h"

const char *nt_translate_link_speed(nt_link_speed_t link_speed)
{
	switch (link_speed) {
	case NT_LINK_SPEED_UNKNOWN:
		return "NotAvail";

	case NT_LINK_SPEED_10M:
		return "10M";

	case NT_LINK_SPEED_100M:
		return "100M";

	case NT_LINK_SPEED_1G:
		return "1G";

	case NT_LINK_SPEED_10G:
		return "10G";

	case NT_LINK_SPEED_25G:
		return "25G";

	case NT_LINK_SPEED_40G:
		return "40G";

	case NT_LINK_SPEED_50G:
		return "50G";

	case NT_LINK_SPEED_100G:
		return "100G";

	default:
		/* DEBUG assert: remind developer that a switch/case entry is needed here.... */
		assert(false);
		return "Unhandled";
	}
}

uint64_t nt_get_link_speed(nt_link_speed_t e_link_speed)
{
	uint64_t n_link_speed = 0ULL;

	switch (e_link_speed) {
	case NT_LINK_SPEED_UNKNOWN:
		n_link_speed = 0UL;
		break;

	case NT_LINK_SPEED_10M:
		n_link_speed = (10ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_100M:
		n_link_speed = (100ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_1G:
		n_link_speed = (1ULL * 1000ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_10G:
		n_link_speed = (10ULL * 1000ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_25G:
		n_link_speed = (25ULL * 1000ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_40G:
		n_link_speed = (40ULL * 1000ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_50G:
		n_link_speed = (50ULL * 1000ULL * 1000ULL * 1000ULL);
		break;

	case NT_LINK_SPEED_100G:
		n_link_speed = (100ULL * 1000ULL * 1000ULL * 1000ULL);
		break;

	default:
		/* DEBUG assert: remind developer that a switch/case entry is needed here.... */
		assert(false);
		n_link_speed = 0UL;
		break;
	}

	return n_link_speed;
}

uint64_t nt_get_max_link_speed(uint32_t link_speed_mask)
{
	uint64_t n_link_speed = 0UL;

	for (int i = 0; i < 32; i++) {
		if ((1U << i) & link_speed_mask) {
			uint64_t link_speed = nt_get_link_speed(1 << i);

			if (link_speed > n_link_speed)
				n_link_speed = link_speed;
		}
	}

	return n_link_speed;
}

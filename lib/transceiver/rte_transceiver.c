/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Roman Khromenok
 */

#include <errno.h>
#include <stddef.h>

#include <eal_export.h>

#include "rte_transceiver.h"
#include "sff_common.h"

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_transceiver_decode, 27.03)
int
rte_transceiver_decode(uint32_t type, const uint8_t *data, uint32_t length,
		rte_transceiver_field_cb cb, void *arg)
{
	struct sff_output out = { .field_cb = cb, .arg = arg };

	if (data == NULL || cb == NULL)
		return -EINVAL;

	return sff_decode_module_eeprom(type, data, length, &out);
}

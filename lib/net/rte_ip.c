/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <string.h>
#include <rte_ip.h>

int32_t
rte_ip_parse_addr(const char *src_ip, uint32_t *output_addr)
{
	int32_t ret = 0;
	char *current_position;

	if (src_ip == NULL)
		return -1;

	char *tok = strdup(src_ip);
	if (tok == NULL)
		return -1;

	char *current_digit = strtok_r(tok, ".", &current_position);

	*output_addr = 0;
	uint32_t i = 0;
	while (current_digit) {
		uint32_t shift = ((3 - i) * 8);
		unsigned long parsed_value = strtoul(current_digit, NULL, 0)
								<< shift;

		if (parsed_value == 0 && strcmp(current_digit, "0"))
			break;

		*output_addr |= parsed_value;
		current_digit = strtok_r(NULL, ".", &current_position);
		i++;

	}
	if (i != 4)
		return -1;

	free(tok);
	return ret;
}

int32_t
rte_ip_print_addr(uint32_t ip_addr, char *buffer, uint32_t buffer_size)
{
	if (buffer == NULL)
		return -1;

	snprintf(buffer, buffer_size, "%u.%u.%u.%u",
		(ip_addr >> 24),
		(ip_addr >> 16) & UINT8_MAX,
		(ip_addr >> 8) & UINT8_MAX,
		 ip_addr & UINT8_MAX);

	return 0;
}

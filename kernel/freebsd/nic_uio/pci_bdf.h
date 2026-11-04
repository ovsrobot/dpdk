/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef _PCI_BDF_H_
#define _PCI_BDF_H_

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/systm.h>
#else
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#endif

struct pci_bdf {
	uint32_t domain;
	uint32_t bus;
	uint32_t devid;
	uint32_t function;
};

static inline int
pci_bdf_parse_linux(const char *token, const size_t token_len, unsigned long *values)
{
	static const char *long_fmt = "FFFF:FF:FF.F";
	static const char *short_fmt = "FF:FF.F";
	const char *fmt = NULL;
	int bus_ofs = 0;

	if (token_len == strlen(long_fmt))
		fmt = long_fmt;
	else if (token_len == strlen(short_fmt))
		fmt = short_fmt;
	else
		return EINVAL;

	/* validate the token against the expected format */
	for (size_t i = 0; i < token_len; i++)
		if (fmt[i] == 'F') {
			if (!isxdigit((unsigned char)token[i]))
				return EINVAL;
		} else if (token[i] != fmt[i])
			return EINVAL;

	if (fmt == long_fmt) {
		values[0] = strtoul(token, NULL, 16);
		bus_ofs = 5;
	}
	values[1] = strtoul(token + bus_ofs, NULL, 16);
	values[2] = strtoul(token + bus_ofs + 3, NULL, 16);
	values[3] = strtoul(token + bus_ofs + 6, NULL, 16);
	return 0;
}

static inline int
pci_bdf_parse_bsd(const char *token, unsigned long *values)
{
	char *endptr;

	/* skip the "pci" prefix if present */
	if (strncmp(token, "pci", 3) == 0) {
		token += 3;
		if (!isdigit((unsigned char)*token))
			return EINVAL;

		values[0] = strtoul(token, &endptr, 10);
		if (*endptr != ':' || !isdigit((unsigned char)*(endptr + 1)))
			return EINVAL;
		token = endptr + 1;
	} else if (!isdigit((unsigned char)*token))
		return EINVAL;

	/* parse bus */
	values[1] = strtoul(token, &endptr, 10);
	if (*endptr != ':' || !isdigit((unsigned char)*(endptr + 1)))
		return EINVAL;
	token = endptr + 1;
	/* parse device */
	values[2] = strtoul(token, &endptr, 10);
	if (*endptr != ':' || !isdigit((unsigned char)*(endptr + 1)))
		return EINVAL;
	token = endptr + 1;
	/* parse function */
	values[3] = strtoul(token, &endptr, 10);
	if (*endptr != '\0')
		return EINVAL;

	return 0;
}

/*
 * Parse a hexadecimal DPDK or decimal FreeBSD PCI address.
 * Return zero on success or EINVAL on failure, leaving bdf unchanged on failure.
 */
static inline int
pci_bdf_parse(const char *token, struct pci_bdf *bdf)
{
	static const unsigned long bdf_field_limits[4] = {UINT16_MAX, 255, 31, 7};
	const size_t token_len = strlen(token);
	unsigned long values[4] = {0};

	if (token_len < 5)
		return EINVAL;

	/* linux uses '.' for final separator */
	int ret = token[token_len - 2] == '.' ?
			pci_bdf_parse_linux(token, token_len, values) :
			pci_bdf_parse_bsd(token, values);
	if (ret != 0)
		return ret;

	for (int i = 0; i < 4; i++)
		if (values[i] > bdf_field_limits[i])
			return EINVAL;

	bdf->domain = values[0];
	bdf->bus = values[1];
	bdf->devid = values[2];
	bdf->function = values[3];
	return 0;
}

#endif /* _PCI_BDF_H_ */

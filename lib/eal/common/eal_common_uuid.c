/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 1996, 1997 Theodore Ts'o.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include <rte_stdatomic.h>
#include <rte_random.h>
#include <rte_time.h>
#include <rte_uuid.h>
#include <rte_os_shim.h>

/* UUID packed form */
struct uuid {
	uint32_t	time_low;
	uint16_t	time_mid;
	uint16_t	time_hi_and_version;
	uint16_t	clock_seq;
	uint8_t		node[6];
};

static void uuid_pack(const struct uuid *uu, rte_uuid_t ptr)
{
	uint32_t tmp;
	uint8_t	*out = ptr;

	tmp = uu->time_low;
	out[3] = (uint8_t) tmp;
	tmp >>= 8;
	out[2] = (uint8_t) tmp;
	tmp >>= 8;
	out[1] = (uint8_t) tmp;
	tmp >>= 8;
	out[0] = (uint8_t) tmp;

	tmp = uu->time_mid;
	out[5] = (uint8_t) tmp;
	tmp >>= 8;
	out[4] = (uint8_t) tmp;

	tmp = uu->time_hi_and_version;
	out[7] = (uint8_t) tmp;
	tmp >>= 8;
	out[6] = (uint8_t) tmp;

	tmp = uu->clock_seq;
	out[9] = (uint8_t) tmp;
	tmp >>= 8;
	out[8] = (uint8_t) tmp;

	memcpy(out+10, uu->node, 6);
}

static void uuid_unpack(const rte_uuid_t in, struct uuid *uu)
{
	const uint8_t *ptr = in;
	uint32_t tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	tmp = (tmp << 8) | *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->time_low = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->time_mid = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->time_hi_and_version = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->clock_seq = tmp;

	memcpy(uu->node, ptr, 6);
}

bool rte_uuid_is_null(const rte_uuid_t uu)
{
	const uint8_t *cp = uu;
	int i;

	for (i = 0; i < 16; i++)
		if (*cp++)
			return false;
	return true;
}

/*
 * rte_uuid_compare() - compare two UUIDs.
 */
int rte_uuid_compare(const rte_uuid_t uu1, const rte_uuid_t uu2)
{
	struct uuid	uuid1, uuid2;

	uuid_unpack(uu1, &uuid1);
	uuid_unpack(uu2, &uuid2);

#define UUCMP(u1, u2) \
	do { if (u1 != u2) return (u1 < u2) ? -1 : 1; } while (0)

	UUCMP(uuid1.time_low, uuid2.time_low);
	UUCMP(uuid1.time_mid, uuid2.time_mid);
	UUCMP(uuid1.time_hi_and_version, uuid2.time_hi_and_version);
	UUCMP(uuid1.clock_seq, uuid2.clock_seq);
#undef UUCMP

	return memcmp(uuid1.node, uuid2.node, 6);
}

int rte_uuid_parse(const char *in, rte_uuid_t uu)
{
	struct uuid	uuid;
	int		i;
	const char	*cp;
	char		buf[3];

	if (strlen(in) != 36)
		return -1;

	for (i = 0, cp = in; i <= 36; i++, cp++) {
		if ((i == 8) || (i == 13) || (i == 18) ||
		    (i == 23)) {
			if (*cp == '-')
				continue;
			else
				return -1;
		}
		if (i == 36)
			if (*cp == 0)
				continue;
		if (!isxdigit(*cp))
			return -1;
	}

	uuid.time_low = strtoul(in, NULL, 16);
	uuid.time_mid = strtoul(in+9, NULL, 16);
	uuid.time_hi_and_version = strtoul(in+14, NULL, 16);
	uuid.clock_seq = strtoul(in+19, NULL, 16);
	cp = in+24;
	buf[2] = 0;

	for (i = 0; i < 6; i++) {
		buf[0] = *cp++;
		buf[1] = *cp++;
		uuid.node[i] = strtoul(buf, NULL, 16);
	}

	uuid_pack(&uuid, uu);
	return 0;
}

void rte_uuid_unparse(const rte_uuid_t uu, char *out, size_t len)
{
	struct uuid uuid;

	uuid_unpack(uu, &uuid);

	snprintf(out, len,
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
		uuid.clock_seq >> 8, uuid.clock_seq & 0xFF,
		uuid.node[0], uuid.node[1], uuid.node[2],
		uuid.node[3], uuid.node[4], uuid.node[5]);
}

void rte_uuid_generate_random(rte_uuid_t out)
{
	union {
		uint64_t words[2];
		rte_uuid_t uuid;
	} buf;
	struct uuid uu;

	/* UUID is 128 bit */
	buf.words[0] = rte_rand();
	buf.words[1] = rte_rand();

	/* Mark these random bytes a version 4 random uuid */
	uuid_unpack(buf.uuid, &uu);
	uu.clock_seq = (uu.clock_seq & 0x3FFF) | 0x8000;
	uu.time_hi_and_version = (uu.time_hi_and_version & 0x0FFF) | 0x4000;
	uuid_pack(&uu, out);
}

void rte_uuid_generate_time(rte_uuid_t out)
{
	struct uuid uu;
	struct timespec ts;
	uint64_t ns, rnd;
	static RTE_ATOMIC(uint16_t) sequence;

	/* The time value for UUID is 100ns since 15 October 1582 */
	clock_gettime(CLOCK_REALTIME, &ts);

	ns = ts.tv_nsec / 100;
	ns += (uint64_t) ts.tv_sec * (NSEC_PER_SEC / 100);
	ns += (((uint64_t) 0x01B21DD2) << 32) + 0x13814000;

	uu.time_low = (uint32_t) ns;
	uu.time_mid = (uint16_t) (ns >> 32);
	uu.time_hi_and_version = (uint16_t) (ns >> 48);
	uu.time_hi_and_version = (uu.time_hi_and_version & 0x0FFF) | 0x4000;
	uu.clock_seq = rte_atomic_fetch_add_explicit(&sequence, 1, rte_memory_order_relaxed);

	rnd = rte_rand();
	memcpy(uu.node, &rnd, 6);
	/*
	 * Follow the convention so that random node part
	 * will not match a valid MAC address,
	 */
	uu.node[0] |= 0x1;

	uuid_pack(&uu, out);
}

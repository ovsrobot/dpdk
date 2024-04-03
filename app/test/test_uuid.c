/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Stephen Hemminger
 */

#include <rte_uuid.h>

#include "test.h"

#define NROUNDS 100

static int
check_duplicate_uuid(rte_uuid_t uids[])
{
	int i, j;
	char out[256];

	for (i = 0; i < NROUNDS - 1; i++) {
		for (j = i + 1; j < NROUNDS; j++) {
			if (rte_uuid_compare(uids[i], uids[j]) == 0) {
				rte_uuid_unparse(uids[i], out, sizeof(out));
				printf("Generated duplicate random uuids %d == %d : %s\n",
				       i, j, out);
				return TEST_FAILED;
			}
		}
	}
	return TEST_SUCCESS;
}


static const struct uuid_case {
	const char *in;
	rte_uuid_t result;
} good_cases[] = {
	{ "02ce8e94-5b84-47fc-8f86-72633c5b5061", RTE_UUID_INIT(0x02ce8e94, 0x5b84, 0x47fc, 0x8f86, 0x72633c5b5061) },
	{ "2c72af87-d220-4931-98ec-45c8520c94e1", RTE_UUID_INIT(0x2c72af87, 0xd220, 0x4931, 0x98ec, 0x45c8520c94e1) },
	{ "441edca1-0942-4ccd-9b33-233e0454fe5b", RTE_UUID_INIT(0x441edca1, 0x0942, 0x4ccd, 0x9b33, 0x233e0454fe5b) },
};

static const char * const bad_cases[] = {
	"",					/* empty */
	"41edca1-0942-4ccd-9b33-233e0454fe5b",  /* too short */
	"d5cecbac-531b-4527-b0629-2bc3011dc9c", /* hyphen in wrong place */
	"db318745-1347-4f5e-m142-d86dc41172b2", /* bad hex */
};

static int
test_uuid(void)
{
	rte_uuid_t uids[NROUNDS] = { };
	rte_uuid_t clone[NROUNDS] = { };
	unsigned int i;
	int ret;

	/* Test generate random uuid */
	for (i = 0; i < NROUNDS; i++) {
		if (!rte_uuid_is_null(uids[i])) {
			printf("Zero'd uuid %d is not null\n", i);
			return TEST_FAILED;
		}

		rte_uuid_generate_random(uids[i]);

		if (rte_uuid_is_null(uids[i])) {
			printf("Generated random uuid %d is null\n", i);
			return TEST_FAILED;
		}
	}

	ret = check_duplicate_uuid(uids);
	if (ret != TEST_SUCCESS)
		return ret;

	/* Test generate time */
	for (i = 0; i < NROUNDS; i++) {
		rte_uuid_generate_time(uids[i]);

		if (rte_uuid_is_null(uids[i])) {
			printf("Generated random uuid %d is null\n", i);
			return TEST_FAILED;
		}
	}


	/* Test that copy works */
	for (i = 0; i < NROUNDS; i++) {
		if (!rte_uuid_is_null(clone[i])) {
			printf("Zero'd clone %d is not null\n", i);
			return TEST_FAILED;
		}

		rte_uuid_copy(clone[i], uids[i]);

		if (rte_uuid_compare(uids[i], clone[i]) != 0) {
			printf("Copied uuid does not match\n");
			return TEST_FAILED;
		}
	}

	for (i = 0; i < RTE_DIM(good_cases); i++) {
		const struct uuid_case *c = &good_cases[i];
		char out[37];
		rte_uuid_t uu;

		if (rte_uuid_parse(c->in, uu) != 0) {
			printf("Failed to parse '%s'\n", c->in);
			return TEST_FAILED;
		}
		if (rte_uuid_compare(uu, c->result) != 0) {
			printf("Parse mismatch for '%s'\n", c->in);
			return TEST_FAILED;
		}

		rte_uuid_unparse(uu, out, sizeof(out));
		if (strcmp(out, c->in) != 0) {
			printf("Parse/unparse mismatch (%s != %s)\n",
			       out, c->in);
			return TEST_FAILED;
		}
	}

	for (i = 0; i < RTE_DIM(bad_cases); i++) {
		const char *s = bad_cases[i];
		rte_uuid_t uu;

		if (rte_uuid_parse(s, uu) == 0) {
			printf("Accepted parse of '%s'\n", s);
			return TEST_FAILED;
		}
	}
	return TEST_SUCCESS;
}


REGISTER_FAST_TEST(uuid_autotest, true, true, test_uuid);

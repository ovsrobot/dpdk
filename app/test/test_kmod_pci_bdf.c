/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#include <rte_common.h>

#include "../../kernel/freebsd/nic_uio/pci_bdf.h"
#include "test.h"

static int
test_kmod_pci_bdf_valid(void)
{
	static const struct {
		const char *address;
		struct pci_bdf expected;
	} cases[] = {
		{"0:0:0", {0, 0, 0, 0}},
		{"42:0:0", {0, 42, 0, 0}},
		{"177:31:7", {0, 177, 31, 7}},
		{"255:31:7", {0, 255, 31, 7}},
		{"pci0:0:0:0", {0, 0, 0, 0}},
		{"pci1:177:31:7", {1, 177, 31, 7}},
		{"pci65535:255:31:7", {65535, 255, 31, 7}},
		{"00:00.0", {0, 0, 0, 0}},
		{"42:00.0", {0, 0x42, 0, 0}},
		{"ff:1f.7", {0, 255, 31, 7}},
		{"FF:1F.7", {0, 255, 31, 7}},
		{"0000:00:00.0", {0, 0, 0, 0}},
		{"0000:98:00.1", {0, 0x98, 0, 1}},
		{"0001:b1:1f.7", {1, 0xb1, 31, 7}},
		{"aBcD:Ab:0F.3", {0xabcd, 0xab, 15, 3}},
		{"ffff:ff:1f.7", {65535, 255, 31, 7}},
	};

	for (size_t i = 0; i < RTE_DIM(cases); i++) {
		struct pci_bdf actual = {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX};
		const struct pci_bdf *expected = &cases[i].expected;
		const char *address = cases[i].address;

		TEST_ASSERT_SUCCESS(pci_bdf_parse(address, &actual),
				"Rejected valid address '%s'", address);
		TEST_ASSERT_EQUAL(actual.domain, expected->domain,
				"Incorrect domain for '%s'", address);
		TEST_ASSERT_EQUAL(actual.bus, expected->bus,
				"Incorrect bus for '%s'", address);
		TEST_ASSERT_EQUAL(actual.devid, expected->devid,
				"Incorrect device for '%s'", address);
		TEST_ASSERT_EQUAL(actual.function, expected->function,
				"Incorrect function for '%s'", address);
	}
	return TEST_SUCCESS;
}

static int
test_kmod_pci_bdf_invalid(void)
{
	static const char * const cases[] = {
		"",
		"0",
		"0:0",
		":0:00",
		"42::0",
		"42:0:",
		"42:0:0:0",
		"42:0:0,43:0:0",
		"pci",
		"pci:42:0:0",
		"pci0::0:0",
		"pci0:42::0",
		"pci0:42:0:",
		"pci0:42:0:0:0",
		"+42:0:0",
		"-0:0:0",
		"42:+0:0",
		"42:0:-0",
		"pci+1:42:0:0",
		"pci-0:42:0:0",
		" 42:0:0",
		"42: 0:0",
		"42:0:0 ",
		"42:0:0\n",
		"42:0:0junk",
		"pci0:af:0:0",
		"af:0:0",
		"0x42:0:0",
		"256:0:0",
		"0:32:0",
		"0:0:8",
		"pci65536:0:0:0",
		"65578:0:0",
		"pci65536:42:0:0",
		"99999999999999999999999999999999999999:0:0",
		"0000:42:0:0",
		"pci0:42:00.0",
		"0000:152:00.0",
		"0000:42:000.0",
		"0000:42:00.000",
		"00000:42:00.0",
		"0:42:00.0",
		"42:0.0",
		"42:00.",
		"42.00:0",
		"42.00.0",
		"0000:gg:00.0",
		"0000:00:20.0",
		"0000:00:00.8",
		"0000:00:00.f",
		"0000:00:00.0junk",
		"\xff:00.0",
	};
	const struct pci_bdf sentinel = {1, 2, 3, 4};

	for (size_t i = 0; i < RTE_DIM(cases); i++) {
		struct pci_bdf actual = sentinel;
		const char *address = cases[i];

		TEST_ASSERT_EQUAL(pci_bdf_parse(address, &actual), EINVAL,
				"Did not reject invalid address '%s' with EINVAL", address);
		TEST_ASSERT(actual.domain == sentinel.domain && actual.bus == sentinel.bus &&
				actual.devid == sentinel.devid &&
				actual.function == sentinel.function,
				"Modified output for invalid address '%s'", address);
	}
	return TEST_SUCCESS;
}

static struct unit_test_suite kmod_pci_bdf_testsuite = {
	.suite_name = "Kernel module PCI BDF parsing",
	.unit_test_cases = {
		TEST_CASE(test_kmod_pci_bdf_valid),
		TEST_CASE(test_kmod_pci_bdf_invalid),
		TEST_CASES_END(),
	},
};

static int
test_kmod_pci_bdf(void)
{
	return unit_test_suite_runner(&kmod_pci_bdf_testsuite);
}

REGISTER_FAST_TEST(kmod_pci_bdf_autotest, NOHUGE_OK, ASAN_OK, test_kmod_pci_bdf);

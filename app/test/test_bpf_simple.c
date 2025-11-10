/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#include "test.h"

#include <rte_bpf.h>
#include <rte_errno.h>

/* Tests of most simple BPF programs (no instructions, one instruction etc.) */

/*
 * Try to load a simple bpf program from the instructions array.
 *
 * When `expected_errno` is zero, expect it to load successfully.
 * When `expected_errno` is non-zero, expect it to fail with this `rte_errno`.
 *
 * @param nb_ins
 *   Number of instructions in the `ins` array.
 * @param ins
 *   BPF instructions array.
 * @param expected_errno
 *   Expected result.
 * @return
 *   TEST_SUCCESS on success, error code on failure.
 */
static int
simple_bpf_load_test(uint32_t nb_ins, const struct ebpf_insn *ins,
	int expected_errno)
{
	const struct rte_bpf_prm prm = {
		.ins = ins,
		.nb_ins = nb_ins,
		.prog_arg = {
			.type = RTE_BPF_ARG_RAW,
			.size = sizeof(uint64_t),
		},
	};

	struct rte_bpf *const bpf = rte_bpf_load(&prm);
	const int actual_errno = rte_errno;
	rte_bpf_destroy(bpf);

	if (expected_errno != 0) {
		RTE_TEST_ASSERT_EQUAL(bpf, NULL,
			"expect rte_bpf_load() == NULL");
		RTE_TEST_ASSERT_EQUAL(actual_errno, expected_errno,
			"expect rte_errno == %d, found %d",
			expected_errno, actual_errno);
	} else
		RTE_TEST_ASSERT_NOT_EQUAL(bpf, NULL,
			"expect rte_bpf_load() != NULL");

	return TEST_SUCCESS;
}

/*
 * Try and load completely empty BPF program.
 * Should fail because there is no EXIT (and also return value is undefined).
 */
static int
test_simple_no_instructions(void)
{
	static const struct ebpf_insn ins[] = {};
	return simple_bpf_load_test(RTE_DIM(ins), ins, EINVAL);
}

REGISTER_FAST_TEST(bpf_simple_no_instructions_autotest, true, true,
	test_simple_no_instructions);

/*
 * Try and load a BPF program comprising single EXIT instruction.
 * Should fail because the return value is undefined.
 */
static int
test_simple_exit_only(void)
{
	static const struct ebpf_insn ins[] = {
		{
			.code = (BPF_JMP | EBPF_EXIT),
		},
	};
	return simple_bpf_load_test(RTE_DIM(ins), ins, EINVAL);
}

REGISTER_FAST_TEST(bpf_simple_exit_only_autotest, true, true,
	test_simple_exit_only);

/*
 * Try and load a BPF program with no EXIT instruction.
 * Should fail because of this.
 */
static int
test_simple_no_exit(void)
{
	static const struct ebpf_insn ins[] = {
		{
			/* Set return value to the program argument. */
			.code = (EBPF_ALU64 | EBPF_MOV | BPF_X),
			.src_reg = EBPF_REG_1,
			.dst_reg = EBPF_REG_0,
		},
	};
	return simple_bpf_load_test(RTE_DIM(ins), ins, EINVAL);
}

REGISTER_FAST_TEST(bpf_simple_no_exit_autotest, true, true,
	test_simple_no_exit);

/*
 * Try and load smallest possible valid BPF program.
 */
static int
test_simple_minimal_working(void)
{
	static const struct ebpf_insn ins[] = {
		{
			/* Set return value to the program argument. */
			.code = (EBPF_ALU64 | EBPF_MOV | BPF_X),
			.src_reg = EBPF_REG_1,
			.dst_reg = EBPF_REG_0,
		},
		{
			.code = (BPF_JMP | EBPF_EXIT),
		},
	};
	return simple_bpf_load_test(RTE_DIM(ins), ins, 0);
}

REGISTER_FAST_TEST(bpf_simple_minimal_working_autotest, true, true,
	test_simple_minimal_working);

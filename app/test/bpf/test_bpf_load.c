/* SPDX-License-Identifier: BSD-3-Clause
 * BPF program for testing rte_bpf_elf_load
 */

#include <stdint.h>
#include <stddef.h>

/* Match the structures from test_bpf.c */
struct dummy_offset {
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	uint8_t  u8;
} __attribute__((packed));

struct dummy_vect8 {
	struct dummy_offset in[8];
	struct dummy_offset out[8];
};

/* External function declaration - provided by test via xsym */
extern void dummy_func1(const void *p, uint32_t *v32, uint64_t *v64);

/*
 * Test BPF function that will be loaded from ELF
 * This function:
 * 1. Reads values from input structure
 * 2. Performs some computations
 * 3. Writes results to output structure
 * 4. Returns sum of values
 */
__attribute__((section("func"), used))
uint64_t
test_func(struct dummy_vect8 *arg)
{
	uint64_t sum = 0;
	uint32_t v32;
	uint64_t v64;

	/* Load input values */
	v32 = arg->in[0].u32;
	v64 = arg->in[0].u64;

	/* Call external function */
	dummy_func1(arg, &v32, &v64);

	/* Store results */
	arg->out[0].u32 = v32;
	arg->out[0].u64 = v64;

	/* Calculate sum */
	sum = arg->in[0].u64;
	sum += arg->in[0].u32;
	sum += arg->in[0].u16;
	sum += arg->in[0].u8;
	sum += v32;
	sum += v64;

	return sum;
}

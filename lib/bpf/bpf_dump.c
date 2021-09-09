/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Stephen Hemminger
 * Based on filter2xdp
 * Copyright (C) 2017 Tobias Klauser
 */

#include <stdio.h>
#include <stdint.h>

#include "rte_bpf.h"

#define BPF_OP_INDEX(x) (BPF_OP(x) >> 4)
#define BPF_SIZE_INDEX(x) (BPF_SIZE(x) >> 3)

static const char *const class_tbl[] = {
	[BPF_LD] = "ld",   [BPF_LDX] = "ldx",	 [BPF_ST] = "st",
	[BPF_STX] = "stx", [BPF_ALU] = "alu",	 [BPF_JMP] = "jmp",
	[BPF_RET] = "ret", [BPF_MISC] = "alu64",
};

static const char *const alu_op_tbl[16] = {
	[BPF_ADD >> 4] = "add",	   [BPF_SUB >> 4] = "sub",
	[BPF_MUL >> 4] = "mul",	   [BPF_DIV >> 4] = "div",
	[BPF_OR >> 4] = "or",	   [BPF_AND >> 4] = "and",
	[BPF_LSH >> 4] = "lsh",	   [BPF_RSH >> 4] = "rsh",
	[BPF_NEG >> 4] = "neg",	   [BPF_MOD >> 4] = "mod",
	[BPF_XOR >> 4] = "xor",	   [EBPF_MOV >> 4] = "mov",
	[EBPF_ARSH >> 4] = "arsh", [EBPF_END >> 4] = "endian",
};

static const char *const size_tbl[] = {
	[BPF_W >> 3] = "w",
	[BPF_H >> 3] = "h",
	[BPF_B >> 3] = "b",
	[EBPF_DW >> 3] = "dw",
};

static const char *const jump_tbl[16] = {
	[BPF_JA >> 4] = "ja",	   [BPF_JEQ >> 4] = "jeq",
	[BPF_JGT >> 4] = "jgt",	   [BPF_JGE >> 4] = "jge",
	[BPF_JSET >> 4] = "jset",  [EBPF_JNE >> 4] = "jne",
	[EBPF_JSGT >> 4] = "jsgt", [EBPF_JSGE >> 4] = "jsge",
	[EBPF_CALL >> 4] = "call", [EBPF_EXIT >> 4] = "exit",
};

static void ebpf_dump(FILE *f, const struct ebpf_insn insn, size_t n)
{
	const char *op, *postfix = "";
	uint8_t cls = BPF_CLASS(insn.code);

	fprintf(f, " L%zu:\t", n);

	switch (cls) {
	default:
		fprintf(f, "unimp 0x%x // class: %s\n", insn.code,
			class_tbl[cls]);
		break;
	case BPF_ALU:
		postfix = "32";
		/* fall through */
	case EBPF_ALU64:
		op = alu_op_tbl[BPF_OP_INDEX(insn.code)];
		if (BPF_SRC(insn.code) == BPF_X)
			fprintf(f, "%s%s r%u, r%u\n", op, postfix, insn.dst_reg,
				insn.src_reg);
		else
			fprintf(f, "%s%s r%u, #0x%x\n", op, postfix,
				insn.dst_reg, insn.imm);
		break;
	case BPF_LD:
		op = "ld";
		postfix = size_tbl[BPF_SIZE_INDEX(insn.code)];
		if (BPF_MODE(insn.code) == BPF_IMM)
			fprintf(f, "%s%s r%d, #0x%x\n", op, postfix,
				insn.dst_reg, insn.imm);
		else if (BPF_MODE(insn.code) == BPF_ABS)
			fprintf(f, "%s%s r%d, [%d]\n", op, postfix,
				insn.dst_reg, insn.imm);
		else if (BPF_MODE(insn.code) == BPF_IND)
			fprintf(f, "%s%s r%d, [r%u + %d]\n", op, postfix,
				insn.dst_reg, insn.src_reg, insn.imm);
		else
			fprintf(f, "// BUG: LD opcode 0x%02x in eBPF insns\n",
				insn.code);
		break;
	case BPF_LDX:
		op = "ldx";
		postfix = size_tbl[BPF_SIZE_INDEX(insn.code)];
		fprintf(f, "%s%s r%d, [r%u + %d]\n", op, postfix, insn.dst_reg,
			insn.src_reg, insn.off);
		break;
#define L(pc, off) ((int)(pc) + 1 + (off))
	case BPF_JMP:
		op = jump_tbl[BPF_OP_INDEX(insn.code)];
		if (op == NULL)
			fprintf(f, "invalid jump opcode: %#x\n", insn.code);
		else if (BPF_OP(insn.code) == BPF_JA)
			fprintf(f, "%s L%d\n", op, L(n, insn.off));
		else if (BPF_OP(insn.code) == EBPF_EXIT)
			fprintf(f, "%s\n", op);
		else
			fprintf(f, "%s r%u, #0x%x, L%d\n", op, insn.dst_reg,
				insn.imm, L(n, insn.off));
		break;
	case BPF_RET:
		fprintf(f, "// BUG: RET opcode 0x%02x in eBPF insns\n",
			insn.code);
		break;
	}
}

void rte_bpf_dump(FILE *f, const struct ebpf_insn *buf, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; ++i)
		ebpf_dump(f, buf[i], i);
}

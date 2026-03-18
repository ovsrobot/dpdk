/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014 IBM Corporation
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 */
#ifndef RTE_CPUFLAGS_RISCV_H
#define RTE_CPUFLAGS_RISCV_H

/**
 * Enumeration of all CPU features supported
 */
enum rte_cpu_flag_t {
	/* Single-letter ISA extensions (detected via AT_HWCAP) */
	RTE_CPUFLAG_RISCV_ISA_A, /* Atomic */
	RTE_CPUFLAG_RISCV_ISA_B, /* Bit-Manipulation */
	RTE_CPUFLAG_RISCV_ISA_C, /* Compressed instruction */
	RTE_CPUFLAG_RISCV_ISA_D, /* Double precision floating-point */
	RTE_CPUFLAG_RISCV_ISA_E, /* RV32E ISA */
	RTE_CPUFLAG_RISCV_ISA_F, /* Single precision floating-point */
	RTE_CPUFLAG_RISCV_ISA_G, /* Extension pack (IMAFD, Zicsr, Zifencei) */
	RTE_CPUFLAG_RISCV_ISA_H, /* Hypervisor */
	RTE_CPUFLAG_RISCV_ISA_I, /* RV32I/RV64I/IRV128I base ISA */
	RTE_CPUFLAG_RISCV_ISA_J, /* Dynamic Translation Language */
	RTE_CPUFLAG_RISCV_ISA_K, /* Reserved */
	RTE_CPUFLAG_RISCV_ISA_L, /* Decimal Floating-Point */
	RTE_CPUFLAG_RISCV_ISA_M, /* Integer Multiply/Divide */
	RTE_CPUFLAG_RISCV_ISA_N, /* User-level interrupts */
	RTE_CPUFLAG_RISCV_ISA_O, /* Reserved */
	RTE_CPUFLAG_RISCV_ISA_P, /* Packed-SIMD */
	RTE_CPUFLAG_RISCV_ISA_Q, /* Quad-precision floating-points */
	RTE_CPUFLAG_RISCV_ISA_R, /* Reserved */
	RTE_CPUFLAG_RISCV_ISA_S, /* Supervisor mode */
	RTE_CPUFLAG_RISCV_ISA_T, /* Transactional memory */
	RTE_CPUFLAG_RISCV_ISA_U, /* User mode */
	RTE_CPUFLAG_RISCV_ISA_V, /* Vector */
	RTE_CPUFLAG_RISCV_ISA_W, /* Reserved */
	RTE_CPUFLAG_RISCV_ISA_X, /* Non-standard extension present */
	RTE_CPUFLAG_RISCV_ISA_Y, /* Reserved */
	RTE_CPUFLAG_RISCV_ISA_Z, /* Reserved */

	/* Z sub-extensions (detected via riscv_hwprobe syscall) */

	/* Bit-manipulation */
	RTE_CPUFLAG_RISCV_ZBA,      /* Address generation (sh1add/sh2add/sh3add) */
	RTE_CPUFLAG_RISCV_ZBB,      /* Basic bit-manipulation (clz/ctz/cpop/rev8) */
	RTE_CPUFLAG_RISCV_ZBC,      /* Carry-less multiply (clmul/clmulh/clmulr) */
	RTE_CPUFLAG_RISCV_ZBS,      /* Single-bit instructions (bset/bclr/binv/bext) */
	RTE_CPUFLAG_RISCV_ZBKB,     /* Bit-manipulation for cryptography */
	RTE_CPUFLAG_RISCV_ZBKC,     /* Carry-less multiply for cryptography */
	RTE_CPUFLAG_RISCV_ZBKX,     /* Crossbar permutations */

	/* Cache management */
	RTE_CPUFLAG_RISCV_ZICBOM,   /* Cache-block management (CMO) */
	RTE_CPUFLAG_RISCV_ZICBOZ,   /* Cache-block zero */

	/* Scalar cryptography */
	RTE_CPUFLAG_RISCV_ZKND,     /* AES decryption */
	RTE_CPUFLAG_RISCV_ZKNE,     /* AES encryption */
	RTE_CPUFLAG_RISCV_ZKNH,     /* SHA-256/512 hash */
	RTE_CPUFLAG_RISCV_ZKSED,    /* SM4 block cipher */
	RTE_CPUFLAG_RISCV_ZKSH,     /* SM3 hash */
	RTE_CPUFLAG_RISCV_ZKT,      /* Data-independent execution latency */

	/* Floating-point */
	RTE_CPUFLAG_RISCV_ZFA,      /* Additional floating-point instructions */
	RTE_CPUFLAG_RISCV_ZFH,      /* Half-precision floating-point */
	RTE_CPUFLAG_RISCV_ZFHMIN,   /* Minimal half-precision floating-point */
	RTE_CPUFLAG_RISCV_ZFBFMIN,  /* BFloat16 conversions */

	/* Compressed instructions */
	RTE_CPUFLAG_RISCV_ZCA,      /* Compressed integer instructions */
	RTE_CPUFLAG_RISCV_ZCB,      /* Additional compressed instructions */
	RTE_CPUFLAG_RISCV_ZCD,      /* Compressed double-precision float */
	RTE_CPUFLAG_RISCV_ZCF,      /* Compressed single-precision float */
	RTE_CPUFLAG_RISCV_ZCMOP,    /* Compressed may-be-operations */

	/* Atomic extensions */
	RTE_CPUFLAG_RISCV_ZAAMO,    /* Atomic memory operations */
	RTE_CPUFLAG_RISCV_ZALRSC,   /* Load-reserved/store-conditional */
	RTE_CPUFLAG_RISCV_ZABHA,    /* Byte/halfword atomics */
	RTE_CPUFLAG_RISCV_ZACAS,    /* Compare-and-swap */

	/* Hints and misc */
	RTE_CPUFLAG_RISCV_ZAWRS,    /* Wait-on-reservation-set (wrs.nto/wrs.sto) */
	RTE_CPUFLAG_RISCV_ZICOND,   /* Integer conditional operations */
	RTE_CPUFLAG_RISCV_ZIHINTNTL,/* Non-temporal locality hints */
	RTE_CPUFLAG_RISCV_ZIHINTPAUSE, /* Pause hint */
	RTE_CPUFLAG_RISCV_ZIMOP,    /* May-be-operations */
	RTE_CPUFLAG_RISCV_ZICNTR,   /* Base counters and timers */
	RTE_CPUFLAG_RISCV_ZIHPM,    /* Hardware performance counters */
	RTE_CPUFLAG_RISCV_ZTSO,     /* Total store ordering */
	RTE_CPUFLAG_RISCV_SUPM,     /* Pointer masking for U-mode */

	/* Vector sub-extensions */
	RTE_CPUFLAG_RISCV_ZVBB,     /* Vector bit-manipulation */
	RTE_CPUFLAG_RISCV_ZVBC,     /* Vector carry-less multiply */
	RTE_CPUFLAG_RISCV_ZVKB,     /* Vector cryptography bit-manipulation */
	RTE_CPUFLAG_RISCV_ZVKG,     /* Vector GCM/GMAC */
	RTE_CPUFLAG_RISCV_ZVKNED,   /* Vector AES block cipher */
	RTE_CPUFLAG_RISCV_ZVKNHA,   /* Vector SHA-256 */
	RTE_CPUFLAG_RISCV_ZVKNHB,   /* Vector SHA-512 */
	RTE_CPUFLAG_RISCV_ZVKSED,   /* Vector SM4 block cipher */
	RTE_CPUFLAG_RISCV_ZVKSH,    /* Vector SM3 hash */
	RTE_CPUFLAG_RISCV_ZVKT,     /* Vector data-independent execution latency */
	RTE_CPUFLAG_RISCV_ZVFH,     /* Vector half-precision float */
	RTE_CPUFLAG_RISCV_ZVFHMIN,  /* Vector minimal half-precision float */
	RTE_CPUFLAG_RISCV_ZVFBFMIN, /* Vector BFloat16 conversions */
	RTE_CPUFLAG_RISCV_ZVFBFWMA, /* Vector BFloat16 widening mul-add */
	RTE_CPUFLAG_RISCV_ZVE32X,   /* Vector 32-bit integer */
	RTE_CPUFLAG_RISCV_ZVE32F,   /* Vector 32-bit float */
	RTE_CPUFLAG_RISCV_ZVE64X,   /* Vector 64-bit integer */
	RTE_CPUFLAG_RISCV_ZVE64F,   /* Vector 64-bit float */
	RTE_CPUFLAG_RISCV_ZVE64D,   /* Vector 64-bit double */
};

#include "generic/rte_cpuflags.h"
#endif /* RTE_CPUFLAGS_RISCV_H */

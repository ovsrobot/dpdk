/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 */
#include <eal_export.h>
#include "rte_cpuflags.h"

#include <elf.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdbool.h>

#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif

#ifndef AT_HWCAP2
#define AT_HWCAP2 26
#endif

#ifndef AT_PLATFORM
#define AT_PLATFORM 15
#endif

/*
 * riscv_hwprobe syscall (Linux 6.4+, syscall number 258).
 * Allows userspace to query ISA extensions not visible via AT_HWCAP.
 * See: linux/arch/riscv/include/uapi/asm/hwprobe.h
 */
#ifndef __NR_riscv_hwprobe
#define __NR_riscv_hwprobe 258
#endif

#ifndef RISCV_HWPROBE_KEY_IMA_EXT_0
#define RISCV_HWPROBE_KEY_IMA_EXT_0	4
#endif

/*
 * Extension bitmasks for RISCV_HWPROBE_KEY_IMA_EXT_0.
 * Defined here for cross-compilation compatibility; guarded to avoid
 * conflicts when the system hwprobe.h is available.
 */
#ifndef RISCV_HWPROBE_EXT_ZBA
#define RISCV_HWPROBE_EXT_ZBA		(1ULL << 3)
#define RISCV_HWPROBE_EXT_ZBB		(1ULL << 4)
#define RISCV_HWPROBE_EXT_ZBS		(1ULL << 5)
#define RISCV_HWPROBE_EXT_ZICBOZ	(1ULL << 6)
#define RISCV_HWPROBE_EXT_ZBC		(1ULL << 7)
#define RISCV_HWPROBE_EXT_ZBKB		(1ULL << 8)
#define RISCV_HWPROBE_EXT_ZBKC		(1ULL << 9)
#define RISCV_HWPROBE_EXT_ZBKX		(1ULL << 10)
#define RISCV_HWPROBE_EXT_ZKND		(1ULL << 11)
#define RISCV_HWPROBE_EXT_ZKNE		(1ULL << 12)
#define RISCV_HWPROBE_EXT_ZKNH		(1ULL << 13)
#define RISCV_HWPROBE_EXT_ZKSED		(1ULL << 14)
#define RISCV_HWPROBE_EXT_ZKSH		(1ULL << 15)
#define RISCV_HWPROBE_EXT_ZKT		(1ULL << 16)
#define RISCV_HWPROBE_EXT_ZVBB		(1ULL << 17)
#define RISCV_HWPROBE_EXT_ZVBC		(1ULL << 18)
#define RISCV_HWPROBE_EXT_ZVKB		(1ULL << 19)
#define RISCV_HWPROBE_EXT_ZVKG		(1ULL << 20)
#define RISCV_HWPROBE_EXT_ZVKNED	(1ULL << 21)
#define RISCV_HWPROBE_EXT_ZVKNHA	(1ULL << 22)
#define RISCV_HWPROBE_EXT_ZVKNHB	(1ULL << 23)
#define RISCV_HWPROBE_EXT_ZVKSED	(1ULL << 24)
#define RISCV_HWPROBE_EXT_ZVKSH		(1ULL << 25)
#define RISCV_HWPROBE_EXT_ZVKT		(1ULL << 26)
#define RISCV_HWPROBE_EXT_ZFH		(1ULL << 27)
#define RISCV_HWPROBE_EXT_ZFHMIN	(1ULL << 28)
#define RISCV_HWPROBE_EXT_ZIHINTNTL	(1ULL << 29)
#define RISCV_HWPROBE_EXT_ZVFH		(1ULL << 30)
#define RISCV_HWPROBE_EXT_ZVFHMIN	(1ULL << 31)
#define RISCV_HWPROBE_EXT_ZFA		(1ULL << 32)
#define RISCV_HWPROBE_EXT_ZTSO		(1ULL << 33)
#define RISCV_HWPROBE_EXT_ZACAS		(1ULL << 34)
#define RISCV_HWPROBE_EXT_ZICOND	(1ULL << 35)
#define RISCV_HWPROBE_EXT_ZIHINTPAUSE	(1ULL << 36)
#define RISCV_HWPROBE_EXT_ZVE32X	(1ULL << 37)
#define RISCV_HWPROBE_EXT_ZVE32F	(1ULL << 38)
#define RISCV_HWPROBE_EXT_ZVE64X	(1ULL << 39)
#define RISCV_HWPROBE_EXT_ZVE64F	(1ULL << 40)
#define RISCV_HWPROBE_EXT_ZVE64D	(1ULL << 41)
#define RISCV_HWPROBE_EXT_ZIMOP		(1ULL << 42)
#define RISCV_HWPROBE_EXT_ZCA		(1ULL << 43)
#define RISCV_HWPROBE_EXT_ZCB		(1ULL << 44)
#define RISCV_HWPROBE_EXT_ZCD		(1ULL << 45)
#define RISCV_HWPROBE_EXT_ZCF		(1ULL << 46)
#define RISCV_HWPROBE_EXT_ZCMOP		(1ULL << 47)
#define RISCV_HWPROBE_EXT_ZAWRS		(1ULL << 48)
#define RISCV_HWPROBE_EXT_SUPM		(1ULL << 49)
#define RISCV_HWPROBE_EXT_ZICNTR	(1ULL << 50)
#define RISCV_HWPROBE_EXT_ZIHPM		(1ULL << 51)
#define RISCV_HWPROBE_EXT_ZFBFMIN	(1ULL << 52)
#define RISCV_HWPROBE_EXT_ZVFBFMIN	(1ULL << 53)
#define RISCV_HWPROBE_EXT_ZVFBFWMA	(1ULL << 54)
#define RISCV_HWPROBE_EXT_ZICBOM	(1ULL << 55)
#define RISCV_HWPROBE_EXT_ZAAMO		(1ULL << 56)
#define RISCV_HWPROBE_EXT_ZALRSC	(1ULL << 57)
#define RISCV_HWPROBE_EXT_ZABHA		(1ULL << 58)
#endif /* RISCV_HWPROBE_EXT_ZBA */

enum cpu_register_t {
	REG_NONE = 0,
	REG_HWCAP,
	REG_HWCAP2,
	REG_PLATFORM,
	REG_HWPROBE_EXT0,  /* riscv_hwprobe RISCV_HWPROBE_KEY_IMA_EXT_0 */
	REG_MAX
};

typedef uint64_t hwcap_registers_t[REG_MAX];

/**
 * Struct to hold a processor feature entry
 */
struct feature_entry {
	uint32_t reg;
	uint32_t bit;
#define CPU_FLAG_NAME_MAX_LEN 64
	char name[CPU_FLAG_NAME_MAX_LEN];
};

#define FEAT_DEF(name, reg, bit) \
	[RTE_CPUFLAG_##name] = {reg, bit, #name},

typedef Elf64_auxv_t _Elfx_auxv_t;

const struct feature_entry rte_cpu_feature_table[] = {
	/* Single-letter ISA extensions via AT_HWCAP */
	FEAT_DEF(RISCV_ISA_A,  REG_HWCAP,  0)
	FEAT_DEF(RISCV_ISA_B,  REG_HWCAP,  1)
	FEAT_DEF(RISCV_ISA_C,  REG_HWCAP,  2)
	FEAT_DEF(RISCV_ISA_D,  REG_HWCAP,  3)
	FEAT_DEF(RISCV_ISA_E,  REG_HWCAP,  4)
	FEAT_DEF(RISCV_ISA_F,  REG_HWCAP,  5)
	FEAT_DEF(RISCV_ISA_G,  REG_HWCAP,  6)
	FEAT_DEF(RISCV_ISA_H,  REG_HWCAP,  7)
	FEAT_DEF(RISCV_ISA_I,  REG_HWCAP,  8)
	FEAT_DEF(RISCV_ISA_J,  REG_HWCAP,  9)
	FEAT_DEF(RISCV_ISA_K,  REG_HWCAP, 10)
	FEAT_DEF(RISCV_ISA_L,  REG_HWCAP, 11)
	FEAT_DEF(RISCV_ISA_M,  REG_HWCAP, 12)
	FEAT_DEF(RISCV_ISA_N,  REG_HWCAP, 13)
	FEAT_DEF(RISCV_ISA_O,  REG_HWCAP, 14)
	FEAT_DEF(RISCV_ISA_P,  REG_HWCAP, 15)
	FEAT_DEF(RISCV_ISA_Q,  REG_HWCAP, 16)
	FEAT_DEF(RISCV_ISA_R,  REG_HWCAP, 17)
	FEAT_DEF(RISCV_ISA_S,  REG_HWCAP, 18)
	FEAT_DEF(RISCV_ISA_T,  REG_HWCAP, 19)
	FEAT_DEF(RISCV_ISA_U,  REG_HWCAP, 20)
	FEAT_DEF(RISCV_ISA_V,  REG_HWCAP, 21)
	FEAT_DEF(RISCV_ISA_W,  REG_HWCAP, 22)
	FEAT_DEF(RISCV_ISA_X,  REG_HWCAP, 23)
	FEAT_DEF(RISCV_ISA_Y,  REG_HWCAP, 24)
	FEAT_DEF(RISCV_ISA_Z,  REG_HWCAP, 25)

	/* Z sub-extensions via riscv_hwprobe syscall */

	/* Bit-manipulation */
	FEAT_DEF(RISCV_ZBA, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBA))
	FEAT_DEF(RISCV_ZBB, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBB))
	FEAT_DEF(RISCV_ZBC, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBC))
	FEAT_DEF(RISCV_ZBS, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBS))
	FEAT_DEF(RISCV_ZBKB, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBKB))
	FEAT_DEF(RISCV_ZBKC, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBKC))
	FEAT_DEF(RISCV_ZBKX, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZBKX))

	/* Cache management */
	FEAT_DEF(RISCV_ZICBOM, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZICBOM))
	FEAT_DEF(RISCV_ZICBOZ, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZICBOZ))

	/* Scalar cryptography */
	FEAT_DEF(RISCV_ZKND, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZKND))
	FEAT_DEF(RISCV_ZKNE, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZKNE))
	FEAT_DEF(RISCV_ZKNH, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZKNH))
	FEAT_DEF(RISCV_ZKSED, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZKSED))
	FEAT_DEF(RISCV_ZKSH, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZKSH))
	FEAT_DEF(RISCV_ZKT, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZKT))

	/* Floating-point */
	FEAT_DEF(RISCV_ZFA, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZFA))
	FEAT_DEF(RISCV_ZFH, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZFH))
	FEAT_DEF(RISCV_ZFHMIN, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZFHMIN))
	FEAT_DEF(RISCV_ZFBFMIN, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZFBFMIN))

	/* Compressed instructions */
	FEAT_DEF(RISCV_ZCA, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZCA))
	FEAT_DEF(RISCV_ZCB, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZCB))
	FEAT_DEF(RISCV_ZCD, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZCD))
	FEAT_DEF(RISCV_ZCF, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZCF))
	FEAT_DEF(RISCV_ZCMOP, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZCMOP))

	/* Atomic extensions */
	FEAT_DEF(RISCV_ZAAMO, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZAAMO))
	FEAT_DEF(RISCV_ZALRSC, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZALRSC))
	FEAT_DEF(RISCV_ZABHA, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZABHA))
	FEAT_DEF(RISCV_ZACAS, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZACAS))

	/* Hints and misc */
	FEAT_DEF(RISCV_ZAWRS, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZAWRS))
	FEAT_DEF(RISCV_ZICOND, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZICOND))
	FEAT_DEF(RISCV_ZIHINTNTL, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZIHINTNTL))
	FEAT_DEF(RISCV_ZIHINTPAUSE, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZIHINTPAUSE))
	FEAT_DEF(RISCV_ZIMOP, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZIMOP))
	FEAT_DEF(RISCV_ZICNTR, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZICNTR))
	FEAT_DEF(RISCV_ZIHPM, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZIHPM))
	FEAT_DEF(RISCV_ZTSO, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZTSO))
	FEAT_DEF(RISCV_SUPM, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_SUPM))

	/* Vector sub-extensions */
	FEAT_DEF(RISCV_ZVBB, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVBB))
	FEAT_DEF(RISCV_ZVBC, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVBC))
	FEAT_DEF(RISCV_ZVKB, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKB))
	FEAT_DEF(RISCV_ZVKG, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKG))
	FEAT_DEF(RISCV_ZVKNED, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKNED))
	FEAT_DEF(RISCV_ZVKNHA, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKNHA))
	FEAT_DEF(RISCV_ZVKNHB, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKNHB))
	FEAT_DEF(RISCV_ZVKSED, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKSED))
	FEAT_DEF(RISCV_ZVKSH, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKSH))
	FEAT_DEF(RISCV_ZVKT, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVKT))
	FEAT_DEF(RISCV_ZVFH, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVFH))
	FEAT_DEF(RISCV_ZVFHMIN, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVFHMIN))
	FEAT_DEF(RISCV_ZVFBFMIN, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVFBFMIN))
	FEAT_DEF(RISCV_ZVFBFWMA, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVFBFWMA))
	FEAT_DEF(RISCV_ZVE32X, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVE32X))
	FEAT_DEF(RISCV_ZVE32F, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVE32F))
	FEAT_DEF(RISCV_ZVE64X, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVE64X))
	FEAT_DEF(RISCV_ZVE64F, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVE64F))
	FEAT_DEF(RISCV_ZVE64D, REG_HWPROBE_EXT0, __builtin_ctzll(RISCV_HWPROBE_EXT_ZVE64D))
};

/*
 * Cache for riscv_hwprobe result. hwprobe is a syscall (unlike getauxval
 * which reads in-process memory), so we call it once at startup and cache
 * the result here.
 */
static uint64_t hwprobe_ext0_value;
static bool hwprobe_ext0_valid;

/*
 * Minimal struct matching the kernel's riscv_hwprobe layout.
 * Defined locally for cross-compilation compatibility.
 */
struct rte_riscv_hwprobe {
	int64_t  key;
	uint64_t value;
};

/*
 * Call riscv_hwprobe syscall to query ISA extensions.
 * cpusetsize=0, cpus=NULL means: query all CPUs, return intersection.
 * Silently fails on kernels < 6.4 (returns -ENOSYS); all Z sub-extension
 * flags will report unsupported in that case.
 */
static void
riscv_hwprobe_init(void)
{
	struct rte_riscv_hwprobe pairs[1] = {
		{ .key = RISCV_HWPROBE_KEY_IMA_EXT_0, .value = 0 },
	};
	long ret;

	ret = syscall(__NR_riscv_hwprobe, pairs, 1, 0, NULL, 0);
	if (ret == 0 && pairs[0].key >= 0) {
		hwprobe_ext0_value = pairs[0].value;
		hwprobe_ext0_valid = true;
	}
}

RTE_INIT(riscv_cpu_init)
{
	riscv_hwprobe_init();
}

/*
 * Read all CPU feature sources into the registers array.
 */
static void
rte_cpu_get_features(hwcap_registers_t out)
{
	out[REG_HWCAP]        = rte_cpu_getauxval(AT_HWCAP);
	out[REG_HWCAP2]       = rte_cpu_getauxval(AT_HWCAP2);
	out[REG_HWPROBE_EXT0] = hwprobe_ext0_valid ? hwprobe_ext0_value : 0;
}

/*
 * Checks if a particular flag is available on current machine.
 */
RTE_EXPORT_SYMBOL(rte_cpu_get_flag_enabled)
int
rte_cpu_get_flag_enabled(enum rte_cpu_flag_t feature)
{
	const struct feature_entry *feat;
	hwcap_registers_t regs = {0};

	if ((unsigned int)feature >= RTE_DIM(rte_cpu_feature_table))
		return -ENOENT;

	feat = &rte_cpu_feature_table[feature];
	if (feat->reg == REG_NONE)
		return -EFAULT;

	rte_cpu_get_features(regs);
	return (regs[feat->reg] >> feat->bit) & 1;
}

RTE_EXPORT_SYMBOL(rte_cpu_get_flag_name)
const char *
rte_cpu_get_flag_name(enum rte_cpu_flag_t feature)
{
	if ((unsigned int)feature >= RTE_DIM(rte_cpu_feature_table))
		return NULL;
	return rte_cpu_feature_table[feature].name;
}

RTE_EXPORT_SYMBOL(rte_cpu_get_intrinsics_support)
void
rte_cpu_get_intrinsics_support(struct rte_cpu_intrinsics *intrinsics)
{
	memset(intrinsics, 0, sizeof(*intrinsics));
}

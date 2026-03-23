/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>

#include <errno.h>
#include <stdint.h>
#include <rte_cpuflags.h>
#include <rte_debug.h>

#include "test.h"


/* convenience define */
#define CHECK_FOR_FLAG(x) \
			result = rte_cpu_get_flag_enabled(x);    \
			printf("%s\n", cpu_flag_result(result)); \
			if (result == -ENOENT)                   \
				return -1;

/*
 * Helper function to display result
 */
static inline const char *
cpu_flag_result(int result)
{
	switch (result) {
	case 0:
		return "NOT PRESENT";
	case 1:
		return "OK";
	default:
		return "ERROR";
	}
}



/*
 * CPUID test
 * ===========
 *
 * - Check flags from different registers with rte_cpu_get_flag_enabled()
 */

static int
test_cpuflags(void)
{
	int result;
	printf("\nChecking for flags from different registers...\n");

#ifdef RTE_ARCH_PPC_64
	printf("Check for PPC64:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_PPC64);

	printf("Check for PPC32:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_PPC32);

	printf("Check for VSX:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_VSX);

	printf("Check for DFP:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_DFP);

	printf("Check for FPU:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_FPU);

	printf("Check for SMT:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SMT);

	printf("Check for MMU:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_MMU);

	printf("Check for ALTIVEC:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_ALTIVEC);

	printf("Check for ARCH_2_06:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_ARCH_2_06);

	printf("Check for ARCH_2_07:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_ARCH_2_07);

	printf("Check for ICACHE_SNOOP:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_ICACHE_SNOOP);
#endif

#if defined(RTE_ARCH_ARM) && defined(RTE_ARCH_32)
	printf("Check for NEON:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_NEON);
#endif

#if defined(RTE_ARCH_ARM64)
	printf("Check for FP:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_FP);

	printf("Check for ASIMD:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_NEON);

	printf("Check for EVTSTRM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_EVTSTRM);

	printf("Check for AES:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_AES);

	printf("Check for PMULL:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_PMULL);

	printf("Check for SHA1:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SHA1);

	printf("Check for SHA2:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SHA2);

	printf("Check for CRC32:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_CRC32);

	printf("Check for ATOMICS:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_ATOMICS);

	printf("Check for SVE:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVE);

	printf("Check for SVE2:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVE2);

	printf("Check for SVEAES:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEAES);

	printf("Check for SVEPMULL:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEPMULL);

	printf("Check for SVEBITPERM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEBITPERM);

	printf("Check for SVESHA3:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVESHA3);

	printf("Check for SVESM4:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVESM4);

	printf("Check for FLAGM2:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_FLAGM2);

	printf("Check for FRINT:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_FRINT);

	printf("Check for SVEI8MM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEI8MM);

	printf("Check for SVEF32MM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEF32MM);

	printf("Check for SVEF64MM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEF64MM);

	printf("Check for SVEBF16:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SVEBF16);

	printf("Check for WFXT:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_WFXT);
#endif

#if defined(RTE_ARCH_X86_64) || defined(RTE_ARCH_I686)
	printf("Check for SSE:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SSE);

	printf("Check for SSE2:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SSE2);

	printf("Check for SSE3:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SSE3);

	printf("Check for SSE4.1:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SSE4_1);

	printf("Check for SSE4.2:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_SSE4_2);

	printf("Check for AVX:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_AVX);

	printf("Check for AVX2:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_AVX2);

	printf("Check for AVX512F:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_AVX512F);

	printf("Check for TRBOBST:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_TRBOBST);

	printf("Check for ENERGY_EFF:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_ENERGY_EFF);

	printf("Check for LAHF_SAHF:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LAHF_SAHF);

	printf("Check for 1GB_PG:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_1GB_PG);

	printf("Check for INVTSC:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_INVTSC);
#endif

#if defined(RTE_ARCH_RISCV)

	printf("Check for RISCV_ISA_A:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_A);

	printf("Check for RISCV_ISA_B:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_B);

	printf("Check for RISCV_ISA_C:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_C);

	printf("Check for RISCV_ISA_D:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_D);

	printf("Check for RISCV_ISA_E:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_E);

	printf("Check for RISCV_ISA_F:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_F);

	printf("Check for RISCV_ISA_G:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_G);

	printf("Check for RISCV_ISA_H:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_H);

	printf("Check for RISCV_ISA_I:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_I);

	printf("Check for RISCV_ISA_J:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_J);

	printf("Check for RISCV_ISA_K:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_K);

	printf("Check for RISCV_ISA_L:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_L);

	printf("Check for RISCV_ISA_M:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_M);

	printf("Check for RISCV_ISA_N:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_N);

	printf("Check for RISCV_ISA_O:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_O);

	printf("Check for RISCV_ISA_P:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_P);

	printf("Check for RISCV_ISA_Q:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_Q);

	printf("Check for RISCV_ISA_R:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_R);

	printf("Check for RISCV_ISA_S:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_S);

	printf("Check for RISCV_ISA_T:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_T);

	printf("Check for RISCV_ISA_U:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_U);

	printf("Check for RISCV_ISA_V:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_V);

	printf("Check for RISCV_ISA_W:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_W);

	printf("Check for RISCV_ISA_X:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_X);

	printf("Check for RISCV_ISA_Y:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_Y);

	printf("Check for RISCV_ISA_Z:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ISA_Z);
	printf("Check for RISCV_ZBA:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBA);

	printf("Check for RISCV_ZBB:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBB);

	printf("Check for RISCV_ZBC:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBC);

	printf("Check for RISCV_ZBS:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBS);

	printf("Check for RISCV_ZBKB:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBKB);

	printf("Check for RISCV_ZBKC:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBKC);

	printf("Check for RISCV_ZBKX:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZBKX);

	printf("Check for RISCV_ZICBOM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZICBOM);

	printf("Check for RISCV_ZICBOZ:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZICBOZ);

	printf("Check for RISCV_ZKND:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZKND);

	printf("Check for RISCV_ZKNE:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZKNE);

	printf("Check for RISCV_ZKNH:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZKNH);

	printf("Check for RISCV_ZKSED:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZKSED);

	printf("Check for RISCV_ZKSH:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZKSH);

	printf("Check for RISCV_ZKT:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZKT);

	printf("Check for RISCV_ZFA:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZFA);

	printf("Check for RISCV_ZFH:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZFH);

	printf("Check for RISCV_ZFHMIN:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZFHMIN);

	printf("Check for RISCV_ZFBFMIN:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZFBFMIN);

	printf("Check for RISCV_ZCA:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZCA);

	printf("Check for RISCV_ZCB:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZCB);

	printf("Check for RISCV_ZCD:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZCD);

	printf("Check for RISCV_ZCF:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZCF);

	printf("Check for RISCV_ZCMOP:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZCMOP);

	printf("Check for RISCV_ZAAMO:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZAAMO);

	printf("Check for RISCV_ZALRSC:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZALRSC);

	printf("Check for RISCV_ZABHA:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZABHA);

	printf("Check for RISCV_ZACAS:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZACAS);

	printf("Check for RISCV_ZAWRS:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZAWRS);

	printf("Check for RISCV_ZICOND:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZICOND);

	printf("Check for RISCV_ZIHINTNTL:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZIHINTNTL);

	printf("Check for RISCV_ZIHINTPAUSE:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZIHINTPAUSE);

	printf("Check for RISCV_ZIMOP:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZIMOP);

	printf("Check for RISCV_ZICNTR:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZICNTR);

	printf("Check for RISCV_ZIHPM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZIHPM);

	printf("Check for RISCV_ZTSO:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZTSO);

	printf("Check for RISCV_SUPM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_SUPM);

	printf("Check for RISCV_ZVBB:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVBB);

	printf("Check for RISCV_ZVBC:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVBC);

	printf("Check for RISCV_ZVKB:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKB);

	printf("Check for RISCV_ZVKG:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKG);

	printf("Check for RISCV_ZVKNED:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKNED);

	printf("Check for RISCV_ZVKNHA:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKNHA);

	printf("Check for RISCV_ZVKNHB:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKNHB);

	printf("Check for RISCV_ZVKSED:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKSED);

	printf("Check for RISCV_ZVKSH:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKSH);

	printf("Check for RISCV_ZVKT:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVKT);

	printf("Check for RISCV_ZVFH:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVFH);

	printf("Check for RISCV_ZVFHMIN:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVFHMIN);

	printf("Check for RISCV_ZVFBFMIN:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVFBFMIN);

	printf("Check for RISCV_ZVFBFWMA:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVFBFWMA);

	printf("Check for RISCV_ZVE32X:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVE32X);

	printf("Check for RISCV_ZVE32F:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVE32F);

	printf("Check for RISCV_ZVE64X:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVE64X);

	printf("Check for RISCV_ZVE64F:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVE64F);

	printf("Check for RISCV_ZVE64D:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_RISCV_ZVE64D);
#endif

#if defined(RTE_ARCH_LOONGARCH)
	printf("Check for CPUCFG:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_CPUCFG);

	printf("Check for LAM:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LAM);

	printf("Check for UAL:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_UAL);

	printf("Check for FPU:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_FPU);

	printf("Check for LSX:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LSX);

	printf("Check for LASX:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LASX);

	printf("Check for CRC32:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_CRC32);

	printf("Check for COMPLEX:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_COMPLEX);

	printf("Check for CRYPTO:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_CRYPTO);

	printf("Check for LVZ:\t\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LVZ);

	printf("Check for LBT_X86:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LBT_X86);

	printf("Check for LBT_ARM:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LBT_ARM);

	printf("Check for LBT_MIPS:\t");
	CHECK_FOR_FLAG(RTE_CPUFLAG_LBT_MIPS);
#endif

	return 0;
}

REGISTER_FAST_TEST(cpuflags_autotest, NOHUGE_OK, ASAN_OK, test_cpuflags);

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Microsoft Corporation

cc_avx2_flags = ['/arch:AVX2']
cc_avx512_flags = ['/arch:AVX512']
cc_has_avx512 = true

cpuid_code = '''
    #include <stdio.h>
    #include <stdint.h>
    #include <intrin.h>

    uint32_t f1_ECX = 0;
    uint32_t f1_EDX = 0;
    uint32_t f7_EBX = 0;
    uint32_t f7_ECX = 0;

    void get_support_flags()
    {
        int ids_max;
        int data[4];

        /*
         * Calling __cpuid with 0x0 as the function_id argument
         * gets the number of the highest valid function ID.
         */
        __cpuid(data, 0);
        ids_max = data[0];

        if (1 <= ids_max) {
            __cpuidex(data, 1, 0);
            f1_ECX = data[2];
            f1_EDX = data[3];

            if (7 <= ids_max) {
                __cpuidex(data, 7, 0);
                f7_EBX = data[1];
                f7_ECX = data[2];
            }
        }
    }

    int get_instruction_support()
    {
        get_support_flags();

    #ifdef SSE3
        return (f1_ECX & (1UL << 0)) ? 1 : 0;
    #endif
    #ifdef PCLMUL
        return (f1_ECX & (1UL << 1)) ? 1 : 0;
    #endif
    #ifdef SSSE3
        return (f1_ECX & (1UL << 9)) ? 1 : 0;
    #endif
    #ifdef SSE4_1
        return (f1_ECX & (1UL << 19)) ? 1 : 0;
    #endif
    #ifdef SSE4_2
        return (f1_ECX & (1UL << 20)) ? 1 : 0;
    #endif
    #ifdef AES
        return (f1_ECX & (1UL << 25)) ? 1 : 0;
    #endif
    #ifdef AVX
        return (f1_ECX & (1UL << 28)) ? 1 : 0;
    #endif
    #ifdef RDRND
        return (f1_ECX & (1UL << 30)) ? 1 : 0;
    #endif
    #ifdef SSE
        return (f1_EDX & (1UL << 25)) ? 1 : 0;
    #endif
    #ifdef SSE2
        return (f1_EDX & (1UL << 26)) ? 1 : 0;
    #endif
    #ifdef AVX2
        return (f7_EBX & (1UL << 5)) ? 1 : 0;
    #endif
    #ifdef AVX512F
        return (f7_EBX & (1UL << 16)) ? 1 : 0;
    #endif
    #ifdef AVX512DQ
        return (f7_EBX & (1UL << 17)) ? 1 : 0;
    #endif
    #ifdef RDSEED
        return (f7_EBX & (1UL << 18)) ? 1 : 0;
    #endif
    #ifdef AVX512IFMA
        return (f7_EBX & (1UL << 21)) ? 1 : 0;
    #endif
    #ifdef AVX512CD
        return (f7_EBX & (1UL << 28)) ? 1 : 0;
    #endif
    #ifdef AVX512BW
        return (f7_EBX & (1UL << 30)) ? 1 : 0;
    #endif
    #ifdef AVX512VL
        return (f7_EBX & (1UL << 31)) ? 1 : 0;
    #endif
    #ifdef GFNI
        return (f7_ECX & (1UL << 8)) ? 1 : 0;
    #endif
    #ifdef VPCLMULQDQ
        return (f7_ECX & (1UL << 10)) ? 1 : 0;
    #endif

        return -1;
    }

    int main(int argc, char *argv[])
    {
        int res = get_instruction_support();
        if (res == -1) {
            printf("Unknown instruction set");
            return -1;
        }
        printf("%d", res);

        return 0;
    }
'''

# The data in the table below can be found here:
# https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html
# A tool to easily update this table can be found under devtools/dump-cpu-flags.
# The table only contains CPUs that have SSE4.2, as this instruction set is required by DPDK.
# That means that in addition to the instruction sets mentioned in the table, all these CPUs
# also have ['SSE', 'SSE2', 'SSE3', 'SSEE3', 'SSE4_1', 'SSE4_2']
cpu_type_to_flags = {
       'x86-64-v2': [],
       'x86-64-v3': ['AVX', 'AVX2'],
       'x86-64-v4': ['AVX', 'AVX2', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD'],
         'nehalem': [],
          'corei7': [],
        'westmere': ['PCLMUL'],
     'sandybridge': ['AVX', 'PCLMUL'],
      'corei7-avx': ['AVX', 'PCLMUL'],
       'ivybridge': ['AVX', 'PCLMUL', 'RDRND'],
      'core-avx-i': ['AVX', 'PCLMUL', 'RDRND'],
         'haswell': ['AVX', 'PCLMUL', 'RDRND', 'AVX2'],
       'core-avx2': ['AVX', 'PCLMUL', 'RDRND', 'AVX2'],
       'broadwell': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED'],
         'skylake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES'],
  'skylake-avx512': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD'],
     'cascadelake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD'],
      'cannonlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA'],
      'cooperlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD'],
  'icelake-client': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
  'icelake-server': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
       'tigerlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
      'rocketlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
       'alderlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
      'raptorlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
      'meteorlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
       'gracemont': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
       'arrowlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
     'arrowlake-s': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
       'lunarlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
     'pantherlake': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
  'sapphirerapids': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
   'emeraldrapids': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
   'graniterapids': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
 'graniterapids-d': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
   'diamondrapids': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
      'silvermont': ['PCLMUL', 'RDRND'],
             'slm': ['PCLMUL', 'RDRND'],
        'goldmont': ['PCLMUL', 'RDRND', 'RDSEED', 'AES'],
   'goldmont-plus': ['PCLMUL', 'RDRND', 'RDSEED', 'AES'],
         'tremont': ['PCLMUL', 'RDRND', 'RDSEED', 'AES', 'GFNI'],
    'sierraforest': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
      'grandridge': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
'clearwaterforest': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'GFNI'],
          'bdver1': ['AVX', 'PCLMUL', 'AES'],
          'bdver2': ['AVX', 'PCLMUL', 'AES'],
          'bdver3': ['AVX', 'PCLMUL', 'AES'],
          'bdver4': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'AES'],
          'znver1': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES'],
          'znver2': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES'],
          'znver3': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ'],
          'znver4': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
          'znver5': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES', 'VPCLMULQDQ', 'AVX512F', 'AVX512VL', 'AVX512BW', 'AVX512DQ', 'AVX512CD', 'AVX512IFMA', 'GFNI'],
          'btver2': ['AVX', 'PCLMUL', 'AES'],
        'lujiazui': ['PCLMUL', 'RDRND', 'RDSEED', 'AES'],
        'yongfeng': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES'],
      'shijidadao': ['AVX', 'PCLMUL', 'RDRND', 'AVX2', 'RDSEED', 'AES'],
}

# Determine cpu_flags for a given configuration.
# SSE instructions up to 4.2 are required for DPDK.
cpu_flags = ['SSE', 'SSE2', 'SSE3', 'SSEE3', 'SSE4_1', 'SSE4_2']

message('cpu_instruction_set: @0@'.format(cpu_instruction_set))

if cpu_instruction_set == ''
    # Nothing to do as cpu_flags already holds all the required flags.
elif cpu_instruction_set == 'native'
    # MSVC behaves differently than GCC regarding supported instruction sets.
    # While GCC will create macros like __AVX512F__ when such instruction set is
    # supported by the current CPU, MSVC does not do that. MSVC will create that
    # macro when parameter /arch:AVX512 is passed to the compiler, even when the
    # CPU does not have that instruction set (by design). So there's a need to
    # look at CPUID flags to figure out what is really supported by the CPU, so
    # that the correct /arch value can be passed to the compiler.
    # The macros also need to be explicitly defined, as /arch will not create all
    # macros GCC creates under the same conditions.
    # As an example, /arch:AVX512 creates __AVX512BW__, but does not create __SSE2__.
    # More details available here:
    # https://learn.microsoft.com/en-us/cpp/preprocessor/predefined-macros

    optional_flags = [
            'PCLMUL',
            'AES',
            'AVX',
            'RDRND',
            'AVX2',
            'AVX512F',
            'AVX512BW',
            'AVX512DQ',
            'AVX512VL',
            'AVX512CD',
            'AVX512IFMA',
            'GFNI',
            'RDSEED',
            'VPCLMULQDQ',
    ]
    foreach f:optional_flags
        result = cc.run(cpuid_code, args: '-D@0@'.format(f),
                        name: 'instruction set @0@'.format(f))
        has_instr_set = result.returncode() == 0 and result.stdout() == '1'
        if has_instr_set
            cpu_flags += f
        endif
        message('Target has @0@: @1@'.format(f, has_instr_set))
    endforeach
else
    # An explicit cpu_instruction_set was provided. Get cpu_flags
    # from cpu_type_to_flags table.
    if cpu_instruction_set not in cpu_type_to_flags
        error('CPU not known or not supported. Please update the table with known CPUs if needed.')
    endif
    cpu_flags += cpu_type_to_flags[cpu_instruction_set]
endif

# Now that all cpu_flags are known, set compile_time_cpuflags and also
# machine_args to ensure that the instruction set #defines (like __SSE2__)
# are always present in the preprocessor.
message('cpu_flags: @0@'.format(cpu_flags))

foreach flag:cpu_flags
    machine_args += '/D__@0@__'.format(flag)
    if flag == 'PCLMUL'
        flag = 'PCLMULQDQ'
    elif flag == 'RDRND'
        flag = 'RDRAND'
    endif
    compile_time_cpuflags += ['RTE_CPUFLAG_' + flag]
endforeach

# Per https://learn.microsoft.com/en-us/cpp/build/reference/arch-x64?view=msvc-170
# option '/arch:AVX512' enables all five flags used in the expression below.
target_has_avx512 = ('AVX512F'  in cpu_flags and
                     'AVX512BW' in cpu_flags and
                     'AVX512DQ' in cpu_flags and
                     'AVX512CD' in cpu_flags and
                     'AVX512VL' in cpu_flags)

# Decide which instruction sets should be used by the compiler.
# With MSVC, intrinsic functions are always enabled. However, for the
# compiler to use an extended instruction set for automatically
# generated code "/arch" needs to be passed. So we instruct the compiler
# to use the largest set that is supported by the CPU. It is implied that
# smaller sets than the largest selected are included, as described here:
# https://learn.microsoft.com/en-us/cpp/build/reference/arch-x64?view=msvc-170
if 'RTE_CPUFLAG_AVX512F' in compile_time_cpuflags
    machine_args += ['/arch:AVX512']
elif 'RTE_CPUFLAG_AVX2' in compile_time_cpuflags
    machine_args += ['/arch:AVX2']
elif 'RTE_CPUFLAG_AVX' in compile_time_cpuflags
    machine_args += ['/arch:AVX']
else
    # SSE4.2 is expected to always be available
    machine_args += ['/arch:SSE4.2']
endif

message('machine_args: @0@'.format(machine_args))
message('compile_time_cpuflags: @0@'.format(compile_time_cpuflags))

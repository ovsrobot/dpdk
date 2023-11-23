..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _cross_compile_dpdk:

Cross-compiling DPDK for Different Architectures on Linux
=========================================================

Cross-compiling DPDK for different architectures follows a similar process. Here are the general steps:

1. **Get Compiler and Libraries**: Obtain the cross-compiler toolchain and any required libraries specific to the target architecture.

2. **Build Using Cross-File**: Use Meson to set up the build with a cross-file specific to the target architecture, and then build with Ninja.

Prerequisites
-------------

- NUMA Library (if required)
- Meson and Ninja
- pkg-config for the target architecture
- Specific GNU or LLVM/Clang toolchain for the target architecture

Cross-Compiling DPDK
--------------------

1. **Set Up the Cross Toolchain**: Download and extract the toolchain for the target architecture. Add it to the PATH.

2. **Compile Any Required Libraries**: Compile libraries like NUMA if required.

3. **Cross-Compile DPDK with Meson**:

   .. code-block:: bash

      meson setup cross-build --cross-file <target_machine_configuration>
      ninja -C cross-build

Refer to the specific sections for ARM64, LoongArch, and RISC-V for detailed instructions and architecture-specific considerations.
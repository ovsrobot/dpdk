.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2023 Marvell.

Library dependency
==================

This document defines the qualification criteria for external libraries that may be
used as dependencies in DPDK drivers or libraries.

- **Free availability**: The library must be freely available to build in either source or binary
  form, with a preference for source form.

- **Compiler compatibility**: The library must be able to compile with a DPDK supported compiler
  for the given execution environment. For example, For Linux, the library must be able to compile
  with GCC and/or clang.

- **Documentation**: The library must have adequate documentation for the steps to build it.

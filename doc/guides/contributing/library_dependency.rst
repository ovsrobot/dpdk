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

- **Documentation**: Must have adequate documentation for the steps to build it.

- **Meson build integration**: The library must have standard method like ``pkg-config``
  for seamless integration with DPDK's build environment.

- **Code readability**: When the depended library is optional, use stubs to reduce the ``ifdef``
  clutter to enable better code readability.

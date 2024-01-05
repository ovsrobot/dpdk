.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2024 Marvell.

External Library dependency
===========================

This document defines the qualification criteria for external libraries that may be
used as dependencies in DPDK drivers or libraries.

#. **Documentation:**

   - Must have adequate documentation for the steps to build it.
   - Must have clear license documentation on distribution and usage aspects of external library.

#. **Free availability:**

   - The library must be freely available to build in either source or binary form.
   - It shall be downloadable from a direct link. There shall not be any requirement to explicitly
     login or sign a user agreement.

#. **Usage License:**

   - Both permissive (e.g., BSD-3 or Apache) and non-permissive (e.g., GPLv3) licenses are acceptable.
   - In the case of a permissive license, automatic inclusion in the build process is assumed.
     For non-permissive licenses, an additional build configuration option is required.

#. **Distributions License:**

   - No specific constraints beyond documentation.

#. **Compiler compatibility:**

   - The library must be able to compile with a DPDK supported compiler for the given execution
     environment.
     For example, for Linux, the library must be able to compile with GCC and/or clang.
   - Library may be limited to a specific OS.

#. **Meson build integration:**

   - The library must have standard method like ``pkg-config`` for seamless integration with
     DPDK's build environment.

#. **Code readability:**

   - Optional dependencies should use stubs to minimize ``ifdef`` clutter, promoting improved
     code readability.

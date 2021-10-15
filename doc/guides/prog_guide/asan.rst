.. Copyright (c) <2021>, Intel Corporation
   All rights reserved.

Memory error detect standard tool - AddressSanitizer(ASan)
==========================================================

`AddressSanitizer
<https://github.com/google/sanitizers/wiki/AddressSanitizer>` (ASan)
is a widely-used debugging tool to detect memory access errors.
It helps detect issues like use-after-free, various kinds of buffer
overruns in C/C++ programs, and other similar errors, as well as
printing out detailed debug information whenever an error is detected.

AddressSanitizer is a part of LLVM (3.1+) and GCC (4.8+).

Usage
-----

meson build
^^^^^^^^^^^

To enable ASan in meson build system, use following meson build command:

Example usage::

 gcc :  meson build -Dbuildtype=debug -Db_sanitize=address
        ninja -C build
 clang: meson build -Dbuildtype=debug -Db_lundef=false -Db_sanitize=address
        ninja -C build

.. Note::

  a) DPDK test has been completed in ubuntu18.04/ubuntu20.04/redhat8.3. To compile with gcc in
     centos, libasan needs to be installed separately.
  b) If the program uses cmdline, when a memory bug occurs, need to execute the "stty echo" command.

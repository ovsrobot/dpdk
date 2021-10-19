.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2021 Intel Corporation

Running Address Sanitizer
=========================

`AddressSanitizer
<https://github.com/google/sanitizers/wiki/AddressSanitizer>`_ (ASan)
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

* gcc::

      meson build -Dbuildtype=debug -Db_sanitize=address
      ninja -C build

* clang::

      meson build -Dbuildtype=debug -Db_lundef=false -Db_sanitize=address
      ninja -C build

.. Note::

  a) To compile with gcc in centos, libasan needs to be installed separately.
  b) If the program being tested uses cmdline you will need to execute the
     "stty echo" command when a error occurs.

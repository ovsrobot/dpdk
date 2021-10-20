.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2021 Intel Corporation

Running AddressSanitizer
========================

`AddressSanitizer
<https://github.com/google/sanitizers/wiki/AddressSanitizer>`_ (ASan)
is a widely-used debugging tool to detect memory access errors.
It helps to detect issues like use-after-free, various kinds of buffer
overruns in C/C++ programs, and other similar errors, as well as
printing out detailed debug information whenever an error is detected.

AddressSanitizer is a part of LLVM (3.1+) and GCC (4.8+).

Add following meson build commands to enable ASan in the meson build system:

* gcc::

    -Dbuildtype=debug -Db_sanitize=address

* clang::

    -Dbuildtype=debug -Db_lundef=false -Db_sanitize=address

.. Note::

    a) If compile with gcc in centos, libasan needs to be installed separately.
    b) If the program is tested using cmdline, you may need to execute the
       "stty echo" command when an error occurs.

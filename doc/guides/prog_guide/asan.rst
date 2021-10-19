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

DPDK ASan functionality is currently only supported Linux x86_64.
Support other platforms, need to define ASAN_SHADOW_OFFSET value
according to google ASan document, and configure meson
(config/meson.build).

Example heap-buffer-overflow error
----------------------------------

Following error was reported when ASan was enabled::

    Applied 9 bytes of memory, but accessed the 10th byte of memory,
    so heap-buffer-overflow appeared.

Below code results in this error::

    Add code to helloworld:
    char *p = rte_zmalloc(NULL, 9, 0);
    if (!p) {
        printf("rte_zmalloc error.");
        return -1;
    }
    p[9] = 'a';

The error log::

    ==369953==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7fb17f465809 at pc 0x5652e6707b84 bp 0x7ffea70eea20 sp 0x7ffea70eea10 WRITE of size 1 at 0x7fb17f465809 thread T0
    #0 0x5652e6707b83 in main ../examples/helloworld/main.c:47
    #1 0x7fb94953c0b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #2 0x5652e67079bd in _start (/home/pzh/asan_test/x86_64-native-linuxapp-gcc/examples/dpdk-helloworld+0x8329bd)

    Address 0x7fb17f465809 is a wild pointer.
    SUMMARY: AddressSanitizer: heap-buffer-overflow ../examples/helloworld/main.c:47 in main

Example use-after-free error
----------------------------

Following error was reported when ASan was enabled::

    Applied for 9 bytes of memory, and accessed the first byte after
    released, so heap-use-after-free appeared.

Below code results in this error::

    Add code to helloworld:
    char *p = rte_zmalloc(NULL, 9, 0);
    if (!p) {
        printf("rte_zmalloc error.");
        return -1;
    }
    rte_free(p);
    *p = 'a';

The error log::

    ==417048==ERROR: AddressSanitizer: heap-use-after-free on address 0x7fc83f465800 at pc 0x564308a39b89 bp 0x7ffc8c85bf50 sp 0x7ffc8c85bf40 WRITE of size 1 at 0x7fc83f465800 thread T0
    #0 0x564308a39b88 in main ../examples/helloworld/main.c:48
    #1 0x7fd0079c60b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #2 0x564308a399bd in _start (/home/pzh/asan_test/x86_64-native-linuxapp-gcc/examples/dpdk-helloworld+0x8329bd)

    Address 0x7fc83f465800 is a wild pointer.
    SUMMARY: AddressSanitizer: heap-use-after-free ../examples/helloworld/main.c:48 in main

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

  a) Some of the features of ASan (for example, 'Display memory application location, currently
     displayed as a wild pointer') are not currently supported by DPDK's implementation.
  b) To compile with gcc in centos, libasan needs to be installed separately.
  c) If the program being tested uses cmdline you will need to execute the
     "stty echo" command when a error occurs.

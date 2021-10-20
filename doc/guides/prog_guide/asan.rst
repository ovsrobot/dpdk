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

DPDK ASan functionality is currently only supported on Linux x86_64.
If want to support on other platforms, need to define ASAN_SHADOW_OFFSET
value according to google ASan document, and configure meson file
(config/meson.build).

Example heap-buffer-overflow error
----------------------------------

Add below unit test code in examples/helloworld/main.c::

    Add code to helloworld:
    char *p = rte_zmalloc(NULL, 9, 0);
    if (!p) {
        printf("rte_zmalloc error.");
        return -1;
    }
    p[9] = 'a';

Above code will result in heap-buffer-overflow error if ASan is enabled, because apply 9 bytes of memory but access the tenth byte, detailed error log as below::

    ==369953==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7fb17f465809 at pc 0x5652e6707b84 bp 0x7ffea70eea20 sp 0x7ffea70eea10 WRITE of size 1 at 0x7fb17f465809 thread T0
    #0 0x5652e6707b83 in main ../examples/helloworld/main.c:47
    #1 0x7fb94953c0b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #2 0x5652e67079bd in _start (/home/pzh/asan_test/x86_64-native-linuxapp-gcc/examples/dpdk-helloworld+0x8329bd)

    Address 0x7fb17f465809 is a wild pointer.
    SUMMARY: AddressSanitizer: heap-buffer-overflow ../examples/helloworld/main.c:47 in main

Example use-after-free error
----------------------------

Add below unit test code in examples/helloworld/main.c::

    Add code to helloworld:
    char *p = rte_zmalloc(NULL, 9, 0);
    if (!p) {
        printf("rte_zmalloc error.");
        return -1;
    }
    rte_free(p);
    *p = 'a';

Above code will result in use-after-free error if ASan is enabled, because apply 9 bytes of memory but access the first byte after release, detailed error log as below::

    ==417048==ERROR: AddressSanitizer: heap-use-after-free on address 0x7fc83f465800 at pc 0x564308a39b89 bp 0x7ffc8c85bf50 sp 0x7ffc8c85bf40 WRITE of size 1 at 0x7fc83f465800 thread T0
    #0 0x564308a39b88 in main ../examples/helloworld/main.c:48
    #1 0x7fd0079c60b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #2 0x564308a399bd in _start (/home/pzh/asan_test/x86_64-native-linuxapp-gcc/examples/dpdk-helloworld+0x8329bd)

    Address 0x7fc83f465800 is a wild pointer.
    SUMMARY: AddressSanitizer: heap-use-after-free ../examples/helloworld/main.c:48 in main

Add following meson build commands to enable ASan in the meson build system:

* gcc::

    -Dbuildtype=debug -Db_sanitize=address

* clang::

    -Dbuildtype=debug -Db_lundef=false -Db_sanitize=address

.. Note::

    a) Some of the features of ASan (for example, 'Display memory application location, currently
       displayed as a wild pointer') are not currently supported by DPDK's implementation.
    b) If compile with gcc in centos, libasan needs to be installed separately.
    c) If the program is tested using cmdline, you may need to execute the
       "stty echo" command when an error occurs.

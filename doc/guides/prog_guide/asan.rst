.. Copyright (c) <2021>, Intel Corporation
   All rights reserved.

Memory error detect standard tool - AddressSanitizer(Asan)
==========================================================

AddressSanitizer (ASan) is a google memory error detect
standard tool. It could help to detect use-after-free and
{heap,stack,global}-buffer overflow bugs in C/C++ programs,
print detailed error information when error happens, large
improve debug efficiency.

By referring to its implementation algorithm
(https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm),
enabled heap-buffer-overflow and use-after-free functions on dpdk.
DPDK ASAN function currently only supports on Linux x86_64.

AddressSanitizer is a part of LLVM(3.1+)and GCC(4.8+).

Example heap-buffer-overflow error
----------------------------------

Following error was reported when Asan was enabled::

    app/test/test_asan_heap_buffer_overflow.c:25: Applied 9 bytes
    of memory, but accessed the 10th byte of memory, so heap-buffer-overflow
    appeared.

Below code results in this error::

    char *p = rte_zmalloc(NULL, 9, 0);
    if (!p) {
        printf("rte_zmalloc error.");
        return -1;
    }
    p[9] = 'a';

The error log::

    ==49433==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7f773fafa249 at pc 0x5556b13bdae4 bp 0x7ffeb4965e40 sp 0x7ffeb4965e30 WRITE of size 1 at 0x7f773fafa249 thread T0
    #0 0x5556b13bdae3 in asan_heap_buffer_overflow ../app/test/test_asan_heap_buffer_overflow.c:25
    #1 0x5556b043e9d4 in cmd_autotest_parsed ../app/test/commands.c:71
    #2 0x5556b1cdd4b0 in cmdline_parse ../lib/cmdline/cmdline_parse.c:290
    #3 0x5556b1cd8987 in cmdline_valid_buffer ../lib/cmdline/cmdline.c:26
    #4 0x5556b1ce477a in rdline_char_in ../lib/cmdline/cmdline_rdline.c:421
    #5 0x5556b1cd923e in cmdline_in ../lib/cmdline/cmdline.c:149
    #6 0x5556b1cd9769 in cmdline_interact ../lib/cmdline/cmdline.c:223
    #7 0x5556b045f53b in main ../app/test/test.c:234
    #8 0x7f7f1eba90b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #9 0x5556b043e70d in _start (/home/pzh/yyy/x86_64-native-linuxapp-gcc/app/test/dpdk-test+0x7ce70d)

    Address 0x7f773fafa249 is a wild pointer.
    SUMMARY: AddressSanitizer: heap-buffer-overflow ../app/test/test_asan_heap_buffer_overflow.c:25 in asan_heap_buffer_overflow
    Shadow bytes around the buggy address:
    0x0fef67f573f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0fef67f57400: fa fa 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0fef67f57410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0fef67f57420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0fef67f57430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    =>0x0fef67f57440: 00 00 00 00 00 00 fa fa 00[01]fa 00 00 00 00 00
    0x0fef67f57450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0fef67f57460: 00 00 00 00 00 00 fa fa 00 00 00 00 00 00 00 00
    0x0fef67f57470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0fef67f57480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Example use-after-free error
----------------------------

Following error was reported when Asan was enabled::

    app/test/test_asan_use_after_free.c:26: Applied for 9 bytes of
    memory, and accessed the first byte after released, so
    heap-use-after-free appeared.

Below code results in this error::

	char *p = rte_zmalloc(NULL, 9, 0);
	if (!p) {
        printf("rte_zmalloc error.");
        return -1;
    }
	rte_free(p);
	*p = 'a';

The error log::

    ==49478==ERROR: AddressSanitizer: heap-use-after-free on address 0x7fe2ffafa240 at pc 0x56409b084bc8 bp 0x7ffef62c57d0 sp 0x7ffef62c57c0 WRITE of size 1 at 0x7fe2ffafa240 thread T0
    #0 0x56409b084bc7 in asan_use_after_free ../app/test/test_asan_use_after_free.c:26
    #1 0x56409a1059d4 in cmd_autotest_parsed ../app/test/commands.c:71
    #2 0x56409b9a44b0 in cmdline_parse ../lib/cmdline/cmdline_parse.c:290
    #3 0x56409b99f987 in cmdline_valid_buffer ../lib/cmdline/cmdline.c:26
    #4 0x56409b9ab77a in rdline_char_in ../lib/cmdline/cmdline_rdline.c:421
    #5 0x56409b9a023e in cmdline_in ../lib/cmdline/cmdline.c:149
    #6 0x56409b9a0769 in cmdline_interact ../lib/cmdline/cmdline.c:223
    #7 0x56409a12653b in main ../app/test/test.c:234
    #8 0x7feafafc20b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #9 0x56409a10570d in _start (/home/pzh/yyy/x86_64-native-linuxapp-gcc/app/test/dpdk-test+0x7ce70d)

    Address 0x7fe2ffafa240 is a wild pointer.
    SUMMARY: AddressSanitizer: heap-use-after-free ../app/test/test_asan_use_after_free.c:26 in asan_use_after_free
    Shadow bytes around the buggy address:
    0x0ffcdff573f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57400: fa fa 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57410: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57420: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57430: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    =>0x0ffcdff57440: 00 00 00 00 00 00 00 00[fd]fd fd fd fd fd fd fd
    0x0ffcdff57450: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57460: 00 00 00 00 00 00 fa fa 00 00 00 00 00 00 00 00
    0x0ffcdff57470: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0x0ffcdff57490: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Usage
-----

meson build
^^^^^^^^^^^

To enable Asan in meson build system, use following meson build command:

Example usage::

 meson build -Dbuildtype=debug -Db_lundef=false -Db_sanitize=address
 ninja -C build

.. Note::

  Centos8 needs to install libasan separately.
  If the program uses cmdline, when a memory bug occurs, need to execute the "stty echo" command.

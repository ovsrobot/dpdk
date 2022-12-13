..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 HiSilicon Limited

Memarea Library
===============

Introduction
------------

The memarea library provides an allocator of variable-size objects, it is
oriented towards the application layer, providing 'region-based memory
management' function [1].

The main features are as follows:

* The memory region can be initialized from the following memory sources:

  - HEAP: e.g. invoke ``rte_malloc_socket``.

  - LIBC: e.g. invoke posix_memalign.

  - Another memarea: it can be allocated from another memarea.

* It provides refcnt feature which could be useful in multi-reader scenario.

* It supports MT-safe as long as it's specified at creation time.

Library API Overview
--------------------

The ``rte_memarea_create()`` function is used to create a memarea, the function
returns the pointer to the created memarea or ``NULL`` if the creation failed.

The ``rte_memarea_destroy()`` function is used to destroy a memarea.

Reference
---------

[1] https://en.wikipedia.org/wiki/Region-based_memory_management

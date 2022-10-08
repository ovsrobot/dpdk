..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 HiSilicon Limited

Memarea Library
===============

Introduction
------------

The memarea library provides an allocator of variable-size objects, it is
oriented towards the application layer, which could provides 'region-based
memory management' function [1].

The main features are as follows:

* The allocated object aligned at ``RTE_CACHE_LINE_SIZE`` default.

* The memory region can be initialized from the following memory sources:
  a) HEAP: e.g. invoke ``rte_malloc_socket``. b) LIBC: e.g. invoke
  posix_memalign to obtain. c) User provided: it can be from e.g.
  rte_extmem_xxx as long as it is available. d) User provided memarea: it can
  be from another memarea.

* It provides refcnt feature which could be useful in multi-reader scenario.

* It supports MT-safe as long as it's specified at creation time.

Library API Overview
--------------------

The ``rte_memarea_create()`` function is used to create a memarea, the function
returns the pointer to the created memarea or ``NULL`` if the creation failed.

The ``rte_memarea_destroy()`` function is used to destroy a memarea.

The ``rte_memarea_alloc()`` function is used to alloc one memory object from
the memarea.

The ``rte_memarea_free()`` function is used to free one memory object which
allocated by ``rte_memarea_alloc()``.

The ``rte_memarea_update_refcnt()`` function is used to update the memory
object's reference count, if the count reaches zero, the memory object will
be freed to memarea.

+The ``rte_memarea_dump()`` function is used to dump the internal information
+of a memarea.

Reference
---------

[1] https://en.wikipedia.org/wiki/Region-based_memory_management

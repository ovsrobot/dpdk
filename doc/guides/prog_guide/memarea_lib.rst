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

* It facilitate alloc and free of memory with low overhead.

* It's memory source could comes from: 1) System API: e.g. malloc/memalign in
  C library. 2) User provided address: it can be from the rte_malloc API series
  or extended memory as long as it is available. 3) User provided memarea: it
  can be from another memarea.

* The default aligement size is ``RTE_CACHE_LINE_SIZE``.

* It provides refcnt feature which could be useful in some scenes.

* It supports MT-safe as long as it's specified at creation time.

* It provides backup memory mechanism, the memory object could use another
  memarea object as a backup.

Library API Overview
--------------------

The ``rte_memarea_create()`` function is used to create a memarea object, the
function returns the pointer to the created memarea or ``NULL`` if the creation
failed.

The ``rte_memarea_destroy()`` function is used to destroy a memarea object.

The ``rte_memarea_alloc()`` function is used to alloc one memory region from
the memarea object.

The ``rte_memarea_free()`` function is used to free one memory region which
allocated by ``rte_memarea_alloc()``.

The ``rte_memarea_update_refcnt()`` function is used to update the memory
region's reference count, if the count reaches zero, the memory region will
be freed to memarea object.

The ``rte_memarea_dump()`` function is used to dump the internal information
of a memarea object.

Reference
---------

[1] https://en.wikipedia.org/wiki/Region-based_memory_management

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 HiSilicon Limited

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

* It supports MT-safe as long as it's specified at creation time.

* The address returned by the allocator is align to 8B.

Library API Overview
--------------------

The ``rte_memarea_create()`` function is used to create a memarea, the function
returns the pointer to the created memarea or ``NULL`` if the creation failed.

The ``rte_memarea_destroy()`` function is used to destroy a memarea.

Debug Mode
----------

In debug mode, cookies are added at the beginning and end of objects, it will
help debugging buffer overflows.

Debug mode is disabled by default, but can be enabled by setting
``RTE_LIBRTE_MEMAREA_DEBUG`` in ``config/rte_config.h``.

Reference
---------

[1] https://en.wikipedia.org/wiki/Region-based_memory_management

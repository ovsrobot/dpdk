..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Ericsson AB

Fastmem Library
===============

The fastmem library is a fast, general-purpose small-object
allocator for DPDK applications. It lets an application replace
its many per-type mempools — each sized for a single object type
— with a single allocator that handles arbitrary object sizes,
grows on demand, and offers mempool-level performance for the
common allocation and free paths.

Like mempool, fastmem is backed by huge pages, is NUMA-aware,
supports bulk operations, and uses per-lcore caches to reduce
shared-state contention. Unlike mempool, it does not require the
caller to declare object sizes or counts up front.


When to use fastmem
-------------------

Use fastmem when:

* Small objects (up to 1 MiB) are allocated and freed on the
  data path with low, predictable latency requirements.

* Many object types of varying sizes exist and maintaining a
  separate mempool for each is impractical.

* DMA-usable memory with efficient virtual-to-IOVA translation
  is needed.

Do not use fastmem for allocations larger than 1 MiB. Use
``rte_malloc()`` instead.


Initialization and teardown
----------------------------

.. code-block:: c

   /* At startup, after rte_eal_init(). */
   rte_fastmem_init();

   /* Optional: pre-reserve backing memory to avoid latency
    * spikes from on-demand memzone reservation. */
   rte_fastmem_reserve(64 * 1024 * 1024, SOCKET_ID_ANY);

   /* ... application runs ... */

   /* At shutdown, after all allocations have been freed. */
   rte_fastmem_deinit();

Neither ``rte_fastmem_init()`` nor ``rte_fastmem_deinit()`` is
thread-safe; call them from the main lcore during startup and
shutdown.


Allocation and free
-------------------

.. code-block:: c

   void *obj = rte_fastmem_alloc(128, 0, 0);
   /* Use obj... */
   rte_fastmem_free(obj);

``rte_fastmem_alloc()`` allocates on the calling lcore's NUMA
socket. Use ``rte_fastmem_alloc_socket()`` to target a specific
socket or to enable cross-socket fallback with ``SOCKET_ID_ANY``.

Alignment
~~~~~~~~~

When ``align`` is 0, the returned pointer is aligned to at least
``RTE_CACHE_LINE_SIZE``. A non-zero ``align`` must be a power of
two. Specifying an alignment smaller than ``RTE_CACHE_LINE_SIZE``
is permitted but the returned object may then share a cache line
with an adjacent allocation, risking false sharing.

Zeroing
~~~~~~~

Pass ``RTE_FASTMEM_F_ZERO`` to receive zero-initialized memory:

.. code-block:: c

   void *obj = rte_fastmem_alloc(256, 0, RTE_FASTMEM_F_ZERO);


Bulk allocation and free
-------------------------

.. code-block:: c

   void *ptrs[32];

   if (rte_fastmem_alloc_bulk(ptrs, 32, 64, 0, 0) < 0)
       /* handle error */;

   /* Use objects... */

   rte_fastmem_free_bulk(ptrs, 32);

Bulk allocation has all-or-nothing semantics: either all
requested objects are returned, or none are (and ``rte_errno``
is set to ``ENOMEM``).

Bulk free is most efficient when all objects belong to the same
size class; in that case the objects are pushed into the
per-lcore cache in a single operation.


IOVA translation
----------------

Memory returned by fastmem is DMA-usable. To obtain the IOVA
for use in device descriptors:

.. code-block:: c

   rte_iova_t iova = rte_fastmem_virt2iova(obj);

The translation is O(1). The returned IOVA is valid for the
lifetime of the allocation.


NUMA awareness
--------------

``rte_fastmem_alloc()`` allocates on the calling lcore's socket.
``rte_fastmem_alloc_socket()`` accepts an explicit socket ID or
``SOCKET_ID_ANY``:

* Explicit socket: allocate only from that socket; fail with
  ``ENOMEM`` if exhausted.

* ``SOCKET_ID_ANY``: try the caller's local socket first, then
  fall back to other sockets.


Per-lcore caches
----------------

Each EAL thread has a private cache per size class. The common
allocation and free paths operate entirely within this cache,
avoiding locks. Cache misses (empty on alloc, full on free)
trigger a bulk transfer to/from the shared bin under a lock.

Non-EAL threads bypass the cache and take the bin lock on every
operation.

``rte_fastmem_cache_flush()`` drains the calling lcore's caches
back to the shared bins. This is useful after bursty phases to
release idle cached memory.


Threading
---------

All allocation and free functions are thread-safe and may be
called from any thread. An allocation made on one thread may be
freed on any other.

Fastmem uses internal spinlocks. A thread preempted while
holding one delays other threads contending for the same lock
(correctness is not affected, only latency).


Pre-reserving memory
--------------------

By default, fastmem reserves backing memory lazily on first
allocation. ``rte_fastmem_reserve(size, socket_id)`` forces
reservation up front, ensuring subsequent allocations do not
incur memzone-reservation latency:

.. code-block:: c

   /* Reserve 128 MiB on socket 0. */
   rte_fastmem_reserve(128 * 1024 * 1024, 0);

Once reserved, backing memory is never returned to the system
during the allocator's lifetime.

Memory limits
~~~~~~~~~~~~~

``rte_fastmem_set_limit(socket_id, max_bytes)`` caps how much
backing memory may be reserved on a given socket. Once the limit is
reached, allocations that would require new backing memory fail with
``ENOMEM``. The default is ``SIZE_MAX`` (unlimited).
``rte_fastmem_get_limit()`` returns the current limit for a socket.

.. code-block:: c

   /* Allow at most 256 MiB on socket 0. */
   rte_fastmem_set_limit(0, 256 * 1024 * 1024);

   /* Block all growth on socket 1. */
   rte_fastmem_set_limit(1, 0);

Pass ``SOCKET_ID_ANY`` to apply the same limit to all sockets.


Size classes
------------

Fastmem uses power-of-two size classes from 8 bytes to 1 MiB
(18 classes). A request for N bytes is served from the smallest
class >= N. The maximum supported size is queryable via
``rte_fastmem_max_size()``.

With power-of-two classes, worst-case internal fragmentation is
just under 50% (e.g., a 33-byte request occupies a 64-byte
slot). Assuming a uniform distribution of request sizes, the
average waste is 25%. In practice, DPDK workloads tend to
cluster at or near powers of two, so typical waste is lower.

Requests exceeding the maximum are rejected with ``E2BIG``.


Implementation
--------------

Fastmem organizes memory in three layers: backing memzones, slabs,
and per-lcore caches.

Backing memory and slabs
~~~~~~~~~~~~~~~~~~~~~~~~~

Backing memory is obtained from EAL as 128 MiB IOVA-contiguous
memzones, each aligned to 2 MiB. A memzone is partitioned into
64 fixed-size, 2 MiB **slabs**. Slabs are the unit of memory
that moves between size classes: a free slab can be assigned to
any bin on demand, and an empty slab (all objects freed) returns
to the free-slab pool for reuse by another size class.

The 2 MiB slab alignment is the key structural property. Given
any object pointer, the allocator recovers the owning slab by
masking off the low 21 bits — no radix tree, hash table, or
memzone lookup is needed. This makes the free path fast: a
single pointer-mask load reaches the slab header, which
identifies the size class and bin.

Each slab reserves 64 bytes at offset 0 for its header. The
remaining space is divided into fixed-size slots equal to the
size class. Allocated objects carry no per-object metadata; the
full slot is available to the caller.

Three-level allocation hierarchy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Per-lcore cache** — a bounded LIFO stack of free object
   pointers, one per (lcore, size class, socket). Allocation
   pops; free pushes. No lock is needed because only the owning
   lcore accesses its cache.

2. **Bin** — one per (size class, socket). Owns the partial and
   full slab lists. A spinlock serializes bulk transfers between
   the bin and per-lcore caches. Most traffic is absorbed by the
   caches, so bin-lock contention is low.

3. **Free-slab pool** — one per socket. A spinlock protects slab
   acquisition and release. These events are rare relative to
   object-level operations (a single small-object slab serves
   thousands of allocations).

On a cache miss (empty on alloc, full on free), the cache
exchanges objects with the bin in bulk, targeting half-full to
maximize headroom in both directions.

Cache sizing
~~~~~~~~~~~~

Cache capacity varies by size class to bound per-lcore memory
footprint:

* Classes 8 B through 4 KiB: capacity 64.
* Larger classes: capacity halves per class (32, 16, 8, 4),
  flooring at 4.

Even the largest classes remain cached. The capacity curve
ensures that small, frequent allocations get the highest cache
hit rate, while large allocations still avoid the bin lock on
most operations.


Statistics
----------

Fastmem maintains always-on, per-lcore counters that track
allocation and free activity. Statistics are queryable at four
levels of granularity: global summary, per size class, per lcore,
and per lcore per class.

``rte_fastmem_classes()`` returns the number of size classes and
optionally fills an array with their sizes.

See ``rte_fastmem.h`` for the full statistics API.


Secondary Processes
-------------------

Fastmem works transparently in DPDK secondary processes. The shared
state is discovered automatically on first allocation.

Secondary processes do not use per-lcore caches; every allocation and
free acquires the bin spinlock directly. This is acceptable for
control-plane secondaries with low allocation rates. The primary
process should pre-reserve sufficient backing memory with
``rte_fastmem_reserve()`` since secondaries cannot grow the pool.

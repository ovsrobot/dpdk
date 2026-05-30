/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include <eal_export.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_spinlock.h>

#include <rte_fastmem.h>

RTE_LOG_REGISTER_DEFAULT(fastmem_logtype, NOTICE);

#define RTE_LOGTYPE_FASTMEM fastmem_logtype

#define FASTMEM_LOG(level, ...) \
	RTE_LOG_LINE(level, FASTMEM, "" __VA_ARGS__)

#define FASTMEM_MEMZONE_SIZE_LOG2 27                            /* 128 MiB */
#define FASTMEM_MEMZONE_SIZE ((size_t)1 << FASTMEM_MEMZONE_SIZE_LOG2)

#define FASTMEM_SLAB_SIZE_LOG2 21                               /*   2 MiB */
#define FASTMEM_SLAB_SIZE ((size_t)1 << FASTMEM_SLAB_SIZE_LOG2)
#define FASTMEM_SLAB_MASK (FASTMEM_SLAB_SIZE - 1)

#define FASTMEM_SLABS_PER_MEMZONE (FASTMEM_MEMZONE_SIZE / FASTMEM_SLAB_SIZE)

#define FASTMEM_MAX_MEMZONES_PER_SOCKET 64

#define FASTMEM_MIN_CLASS_LOG2 3                                /*   8 B */
#define FASTMEM_MAX_CLASS_LOG2 20                               /*   1 MiB */
#define FASTMEM_N_CLASSES (FASTMEM_MAX_CLASS_LOG2 - FASTMEM_MIN_CLASS_LOG2 + 1)

#define FASTMEM_MIN_SIZE ((size_t)1 << FASTMEM_MIN_CLASS_LOG2)
#define FASTMEM_MAX_ALLOC_SIZE ((size_t)1 << FASTMEM_MAX_CLASS_LOG2)

#define FASTMEM_SLAB_HEADER_SIZE RTE_CACHE_LINE_SIZE

#define FASTMEM_CACHE_BASE_CAPACITY 64
#define FASTMEM_CACHE_FLOOR_CAPACITY 4
#define FASTMEM_CACHE_BASE_CLASS_LOG2 12                        /* 4 KiB */

struct fastmem_bin;

/*
 * Slab header at offset 0 of each 2 MiB slab. Either free (linked
 * via next_free) or assigned to a bin (linked via list).
 */
struct fastmem_slab {
	struct fastmem_bin *bin;
	void *free_head;
	uint32_t free_count;
	uint32_t n_slots;
	struct fastmem_slab *next_free;
	TAILQ_ENTRY(fastmem_slab) list;
	rte_iova_t iova_base;
} __rte_aligned(FASTMEM_SLAB_HEADER_SIZE);

TAILQ_HEAD(fastmem_slab_list, fastmem_slab);

struct fastmem_bin {
	rte_spinlock_t lock;
	uint32_t slot_size;
	uint32_t slots_per_slab;
	uint32_t class_idx;
	struct fastmem_slab_list partial;
	struct fastmem_slab_list full;
	int socket_id;
	uint64_t slab_acquires;
	uint64_t slab_releases;
	uint32_t slabs_partial;
	uint32_t slabs_full;
	/*
	 * Traffic served straight from the bin, with no cache of any kind
	 * backing it. Reached only on the fallback where a caller has no
	 * private per-lcore cache and the shared cache could not be created
	 * either (cache-struct allocation failed, e.g. under a memory limit
	 * or in an under-provisioned secondary). The normal cache-less path
	 * goes through the shared cache and is counted there, not here.
	 * Written under bin->lock, read locklessly by the stats functions.
	 * Not attributable to an lcore, so it appears only in the global and
	 * per-class statistics.
	 */
	uint64_t nocache_allocs;
	uint64_t nocache_frees;
	uint64_t nocache_nomem;
};

/*
 * Bounded LIFO of free object pointers, holding statistics counters
 * alongside the hot-path fields so alloc and free stay on one cache line.
 *
 * Used in two ways: as a private per-(lcore, class, socket) cache for
 * lcore-id-equipped primary threads (written only by its owning lcore, so
 * lock-free), and as a per-(class, socket) cache shared by all other
 * callers (serialized by the socket's shared_cache_lock).
 *
 * Never freed once created (rte_fastmem_cache_flush() drains the objects
 * but keeps the struct), so the counters survive a flush and stats readers
 * may touch it safely.
 */
struct fastmem_cache {
	uint32_t count;
	uint32_t capacity;
	uint32_t target;
	uint64_t alloc_cache_hits;
	uint64_t alloc_cache_misses;
	uint64_t alloc_nomem;
	uint64_t free_cache_hits;
	uint64_t free_cache_misses;
	void *objs[];
} __rte_cache_aligned;

struct fastmem_socket_state {
	rte_spinlock_t lock;
	struct fastmem_slab *free_head;
	size_t reserved_bytes;
	size_t memory_limit;
	unsigned int n_memzones;
	unsigned int memzone_seq;
	const struct rte_memzone *memzones[FASTMEM_MAX_MEMZONES_PER_SOCKET];
	struct fastmem_bin bins[FASTMEM_N_CLASSES];
	struct fastmem_cache *caches[RTE_MAX_LCORE][FASTMEM_N_CLASSES];
	/*
	 * Cache shared by all callers lacking a private per-lcore cache
	 * (lcore-less primary threads and every secondary-process thread),
	 * guarded by one spinlock for the whole socket.
	 */
	rte_spinlock_t shared_cache_lock;
	struct fastmem_cache *shared_caches[FASTMEM_N_CLASSES];
};

struct fastmem {
	struct fastmem_socket_state sockets[RTE_MAX_NUMA_NODES];
};

static struct fastmem *fastmem;
static const struct rte_memzone *fastmem_mz;
static bool fastmem_is_primary; /* cached; avoids function call on hot path */

/*
 * Ensure the global fastmem state is available to this process,
 * lazily attaching a secondary to the shared memzone on first use.
 * Returns false (rte_errno = ENODEV) if the primary has not
 * initialized the library.
 */
static bool
fastmem_assure(void)
{
	const struct rte_memzone *mz;

	if (likely(fastmem != NULL))
		return true;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		rte_errno = ENODEV;
		return false;
	}

	mz = rte_memzone_lookup("fastmem_state");
	if (mz == NULL) {
		rte_errno = ENODEV;
		return false;
	}

	fastmem_mz = mz;
	fastmem = mz->addr;
	return true;
}

static unsigned int
size_to_class(size_t size, size_t align)
{
	size_t effective;
	unsigned int log2;

	effective = size < FASTMEM_MIN_SIZE ? FASTMEM_MIN_SIZE : size;
	if (align > effective)
		effective = align;

	log2 = 64u - rte_clz64(effective - 1);

	if (log2 < FASTMEM_MIN_CLASS_LOG2)
		log2 = FASTMEM_MIN_CLASS_LOG2;
	if (log2 > FASTMEM_MAX_CLASS_LOG2)
		return FASTMEM_N_CLASSES;

	return log2 - FASTMEM_MIN_CLASS_LOG2;
}

static size_t
class_size(unsigned int class_idx)
{
	return (size_t)1 << (class_idx + FASTMEM_MIN_CLASS_LOG2);
}

/**
 * Normalize and validate the alignment argument.
 * Returns true on success (align updated in place), false on invalid input.
 */
static bool
normalize_align(size_t *align)
{
	if (*align == 0) {
		*align = RTE_CACHE_LINE_SIZE;
		return true;
	}
	return rte_is_power_of_2(*align);
}

static_assert(sizeof(struct fastmem_slab) == FASTMEM_SLAB_HEADER_SIZE,
	"fastmem slab header must fit in exactly one cache line");
static_assert(sizeof(struct fastmem_slab) <= FASTMEM_SLAB_SIZE,
	"slab header larger than a slab makes no sense");

static struct fastmem_slab *
slab_of(void *obj)
{
	return (struct fastmem_slab *)
		((uintptr_t)obj & ~(uintptr_t)FASTMEM_SLAB_MASK);
}

static size_t
slab_slot0_offset(size_t class_size)
{
	return class_size < FASTMEM_SLAB_HEADER_SIZE ?
		FASTMEM_SLAB_HEADER_SIZE : class_size;
}

static uint32_t
slab_slot_count(size_t class_size)
{
	size_t offset = slab_slot0_offset(class_size);

	return (uint32_t)((FASTMEM_SLAB_SIZE - offset) / class_size);
}

/* Must be called with bin->lock held. */
static void
slab_init(struct fastmem_bin *bin, struct fastmem_slab *slab)
{
	size_t slot_size = bin->slot_size;
	size_t offset = slab_slot0_offset(slot_size);
	uint32_t n = bin->slots_per_slab;
	void *prev = NULL;
	uint32_t i;

	slab->bin = bin;
	slab->n_slots = n;
	slab->free_count = n;

	/* Build in reverse so pops yield sequential addresses. */
	for (i = 0; i < n; i++) {
		void *slot = RTE_PTR_ADD(slab, offset + i * slot_size);
		*(void **)slot = prev;
		prev = slot;
	}
	slab->free_head = prev;
}

static int
grow_socket(struct fastmem_socket_state *socket, int socket_id)
{
	char name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	unsigned int i;

	if (socket->reserved_bytes + FASTMEM_MEMZONE_SIZE > socket->memory_limit) {
		FASTMEM_LOG(ERR,
			"reserve would exceed memory_limit (%zu) on socket %d",
			socket->memory_limit, socket_id);
		return -ENOMEM;
	}

	if (socket->n_memzones == FASTMEM_MAX_MEMZONES_PER_SOCKET) {
		FASTMEM_LOG(ERR,
			"reached per-socket memzone cap (%u) on socket %d",
			FASTMEM_MAX_MEMZONES_PER_SOCKET, socket_id);
		return -ENOMEM;
	}

	snprintf(name, sizeof(name), "fastmem_%d_%u", socket_id,
			socket->memzone_seq++);

	mz = rte_memzone_reserve_aligned(name, FASTMEM_MEMZONE_SIZE,
			socket_id, RTE_MEMZONE_IOVA_CONTIG,
			FASTMEM_SLAB_SIZE);
	if (mz == NULL) {
		FASTMEM_LOG(ERR,
			"failed to reserve %zu-byte memzone '%s' on socket %d: %s",
			(size_t)FASTMEM_MEMZONE_SIZE, name, socket_id,
			rte_strerror(rte_errno));
		return -ENOMEM;
	}

	socket->memzones[socket->n_memzones++] = mz;
	socket->reserved_bytes += FASTMEM_MEMZONE_SIZE;

	for (i = 0; i < FASTMEM_SLABS_PER_MEMZONE; i++) {
		struct fastmem_slab *slab = RTE_PTR_ADD(mz->addr,
				i * FASTMEM_SLAB_SIZE);

		slab->iova_base = mz->iova + i * FASTMEM_SLAB_SIZE;
		slab->next_free = socket->free_head;
		socket->free_head = slab;
	}

	FASTMEM_LOG(DEBUG,
		"reserved memzone '%s' (%zu bytes) on socket %d; %zu slabs added",
		name, (size_t)FASTMEM_MEMZONE_SIZE, socket_id,
		(size_t)FASTMEM_SLABS_PER_MEMZONE);

	return 0;
}

static struct fastmem_slab *
slab_acquire(struct fastmem_socket_state *socket, int socket_id)
{
	struct fastmem_slab *slab;

	rte_spinlock_lock(&socket->lock);

	if (socket->free_head == NULL) {
		int rc = grow_socket(socket, socket_id);

		if (rc < 0) {
			rte_spinlock_unlock(&socket->lock);
			return NULL;
		}
	}

	slab = socket->free_head;
	socket->free_head = slab->next_free;
	slab->next_free = NULL;

	rte_spinlock_unlock(&socket->lock);

	return slab;
}

static void
slab_release(struct fastmem_socket_state *socket,
		struct fastmem_slab *slab)
{
	rte_spinlock_lock(&socket->lock);

	slab->next_free = socket->free_head;
	socket->free_head = slab;

	rte_spinlock_unlock(&socket->lock);
}

static void
bin_init(struct fastmem_bin *bin, unsigned int class_idx, int socket_id)
{
	size_t slot_size = class_size(class_idx);

	rte_spinlock_init(&bin->lock);
	bin->slot_size = (uint32_t)slot_size;
	bin->slots_per_slab = slab_slot_count(slot_size);
	bin->class_idx = class_idx;
	TAILQ_INIT(&bin->partial);
	TAILQ_INIT(&bin->full);
	bin->socket_id = socket_id;
	bin->slab_acquires = 0;
	bin->slab_releases = 0;
	bin->slabs_partial = 0;
	bin->slabs_full = 0;
}

static void
bin_release(struct fastmem_bin *bin, struct fastmem_socket_state *socket)
{
	struct fastmem_slab *slab;

	while ((slab = TAILQ_FIRST(&bin->partial)) != NULL) {
		TAILQ_REMOVE(&bin->partial, slab, list);
		slab_release(socket, slab);
	}
	while ((slab = TAILQ_FIRST(&bin->full)) != NULL) {
		TAILQ_REMOVE(&bin->full, slab, list);
		slab_release(socket, slab);
	}
}

static unsigned int
bin_pop_locked(struct fastmem_bin *bin, void **objs, unsigned int n)
{
	unsigned int got = 0;

	while (got < n) {
		struct fastmem_slab *slab = TAILQ_FIRST(&bin->partial);
		void *obj;

		if (slab == NULL)
			break;

		obj = slab->free_head;
		slab->free_head = *(void **)obj;
		slab->free_count--;
		objs[got++] = obj;

		if (slab->free_count == 0) {
			TAILQ_REMOVE(&bin->partial, slab, list);
			TAILQ_INSERT_HEAD(&bin->full, slab, list);
			bin->slabs_partial--;
			bin->slabs_full++;
		}
	}

	return got;
}

/*
 * Fully-drained slabs are accumulated in @p to_release for the
 * caller to return after dropping the lock.
 */
static unsigned int
bin_push_locked(struct fastmem_bin *bin, void **objs, unsigned int n,
		struct fastmem_slab **to_release)
{
	unsigned int n_release = 0;
	unsigned int i;

	for (i = 0; i < n; i++) {
		void *obj = objs[i];
		struct fastmem_slab *slab = (struct fastmem_slab *)
			((uintptr_t)obj & ~(uintptr_t)FASTMEM_SLAB_MASK);
		bool was_full = slab->free_count == 0;

		*(void **)obj = slab->free_head;
		slab->free_head = obj;
		slab->free_count++;

		if (was_full) {
			TAILQ_REMOVE(&bin->full, slab, list);
			TAILQ_INSERT_HEAD(&bin->partial, slab, list);
			bin->slabs_full--;
			bin->slabs_partial++;
		}

		if (slab->free_count == slab->n_slots) {
			TAILQ_REMOVE(&bin->partial, slab, list);
			bin->slabs_partial--;
			bin->slab_releases++;
			to_release[n_release++] = slab;
		}
	}

	return n_release;
}

/*
 * Allocate a single object from the bin. Pass @p nocache true only on the
 * no-cache fallback (a user allocation that has neither a private nor a
 * shared cache); it counts the alloc against the bin's no-cache statistics.
 * Internal cache machinery (refills) passes false.
 */
static void *
bin_alloc_one(struct fastmem_bin *bin, bool nocache)
{
	struct fastmem_socket_state *socket = &fastmem->sockets[bin->socket_id];
	void *obj;

	rte_spinlock_lock(&bin->lock);

	while (bin_pop_locked(bin, &obj, 1) == 0) {
		struct fastmem_slab *slab;

		if (TAILQ_FIRST(&bin->partial) != NULL)
			continue;

		rte_spinlock_unlock(&bin->lock);

		slab = slab_acquire(socket, bin->socket_id);
		if (slab == NULL) {
			rte_errno = ENOMEM;
			return NULL;
		}

		rte_spinlock_lock(&bin->lock);

		if (unlikely(TAILQ_FIRST(&bin->partial) != NULL)) {
			/* Release surplus slab without holding bin->lock. */
			rte_spinlock_unlock(&bin->lock);
			slab_release(socket, slab);
			rte_spinlock_lock(&bin->lock);
		} else {
			slab_init(bin, slab);
			TAILQ_INSERT_HEAD(&bin->partial, slab, list);
			bin->slabs_partial++;
			bin->slab_acquires++;
		}
	}

	if (nocache)
		bin->nocache_allocs++;

	rte_spinlock_unlock(&bin->lock);

	return obj;
}

/*
 * Allocate up to @p n objects from the bin. Pass @p nocache true only on the
 * no-cache fallback (a user allocation that has neither a private nor a
 * shared cache); it counts the allocs against the bin's no-cache statistics.
 * Internal cache machinery (e.g. a cache refill) passes false.
 */
static unsigned int
bin_alloc_bulk(struct fastmem_bin *bin, void **objs, unsigned int n,
		bool nocache)
{
	struct fastmem_socket_state *socket = &fastmem->sockets[bin->socket_id];
	unsigned int got = 0;

	rte_spinlock_lock(&bin->lock);

	while (got < n) {
		struct fastmem_slab *slab;

		got += bin_pop_locked(bin, objs + got, n - got);
		if (got == n)
			break;

		if (TAILQ_FIRST(&bin->partial) != NULL)
			continue;

		rte_spinlock_unlock(&bin->lock);

		slab = slab_acquire(socket, bin->socket_id);
		if (slab == NULL) {
			rte_spinlock_lock(&bin->lock);
			break;
		}

		rte_spinlock_lock(&bin->lock);

		if (unlikely(TAILQ_FIRST(&bin->partial) != NULL)) {
			/* Release surplus slab without holding bin->lock. */
			rte_spinlock_unlock(&bin->lock);
			slab_release(socket, slab);
			rte_spinlock_lock(&bin->lock);
		} else {
			slab_init(bin, slab);
			TAILQ_INSERT_HEAD(&bin->partial, slab, list);
			bin->slabs_partial++;
			bin->slab_acquires++;
		}
	}

	if (nocache)
		bin->nocache_allocs += got;

	rte_spinlock_unlock(&bin->lock);

	return got;
}

/*
 * Free a single object to the bin. Pass @p nocache true only on the no-cache
 * fallback (a user free that has neither a private nor a shared cache); it
 * counts the free against the bin's no-cache statistics. Internal cache
 * machinery (drain, teardown, flush) passes false.
 */
static void
bin_free_one(struct fastmem_bin *bin, void *obj, bool nocache)
{
	unsigned int n_release;
	struct fastmem_slab *slab_to_release = NULL;
	struct fastmem_socket_state *socket;

	rte_spinlock_lock(&bin->lock);
	n_release = bin_push_locked(bin, &obj, 1, &slab_to_release);
	if (nocache)
		bin->nocache_frees++;
	rte_spinlock_unlock(&bin->lock);

	if (n_release > 0) {
		socket = &fastmem->sockets[bin->socket_id];
		slab_release(socket, slab_to_release);
	}
}

/*
 * Free a batch of objects to the bin. Always internal cache machinery
 * (drain, teardown, flush), never a no-cache user free, so unlike
 * bin_free_one() it has no nocache flag and is never counted against the
 * bin's no-cache statistics.
 */
static void
bin_free_bulk(struct fastmem_bin *bin, void **objs, unsigned int n)
{
	struct fastmem_socket_state *socket = &fastmem->sockets[bin->socket_id];
	struct fastmem_slab *to_release[FASTMEM_CACHE_BASE_CAPACITY];
	unsigned int n_release;
	unsigned int i;

	RTE_VERIFY(n <= RTE_DIM(to_release));

	rte_spinlock_lock(&bin->lock);
	n_release = bin_push_locked(bin, objs, n, to_release);
	rte_spinlock_unlock(&bin->lock);

	for (i = 0; i < n_release; i++)
		slab_release(socket, to_release[i]);
}

static unsigned int
cache_capacity(unsigned int class_idx)
{
	unsigned int class_log2 = class_idx + FASTMEM_MIN_CLASS_LOG2;
	unsigned int shift;
	unsigned int cap;

	if (class_log2 <= FASTMEM_CACHE_BASE_CLASS_LOG2)
		return FASTMEM_CACHE_BASE_CAPACITY;

	shift = class_log2 - FASTMEM_CACHE_BASE_CLASS_LOG2;
	cap = FASTMEM_CACHE_BASE_CAPACITY >> shift;

	return cap < FASTMEM_CACHE_FLOOR_CAPACITY ?
		FASTMEM_CACHE_FLOOR_CAPACITY : cap;
}

static struct fastmem_cache **
cache_slot(struct fastmem_socket_state *socket, unsigned int class_idx,
		unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE)
		return NULL;
	return &socket->caches[lcore_id][class_idx];
}

/*
 * Allocate and initialize a cache struct, itself drawn from fastmem on the
 * calling lcore's socket, bypassing the cache layer to avoid recursion.
 */
static struct fastmem_cache *
cache_alloc(struct fastmem_socket_state *socket, unsigned int class_idx)
{
	struct fastmem_cache *cache;
	unsigned int capacity = cache_capacity(class_idx);
	size_t cache_size = sizeof(*cache) + capacity * sizeof(void *);
	unsigned int cache_class = size_to_class(cache_size, RTE_CACHE_LINE_SIZE);
	unsigned int own_socket = rte_socket_id();
	struct fastmem_socket_state *alloc_socket;

	if (cache_class >= FASTMEM_N_CLASSES) {
		FASTMEM_LOG(ERR,
			"cache size %zu exceeds max size class",
			cache_size);
		return NULL;
	}

	if (own_socket >= RTE_MAX_NUMA_NODES)
		own_socket = (unsigned int)socket->bins[0].socket_id;

	alloc_socket = &fastmem->sockets[own_socket];

	cache = bin_alloc_one(&alloc_socket->bins[cache_class], false);
	if (cache == NULL) {
		FASTMEM_LOG(ERR,
			"failed to allocate cache for class %u on socket %u",
			class_idx, own_socket);
		return NULL;
	}

	cache->count = 0;
	cache->capacity = capacity;
	cache->target = capacity / 2;
	cache->alloc_cache_hits = 0;
	cache->alloc_cache_misses = 0;
	cache->alloc_nomem = 0;
	cache->free_cache_hits = 0;
	cache->free_cache_misses = 0;

	return cache;
}

static struct fastmem_cache *
cache_create(struct fastmem_socket_state *socket,
		unsigned int class_idx, unsigned int lcore_id)
{
	struct fastmem_cache **slot = cache_slot(socket, class_idx, lcore_id);
	struct fastmem_cache *cache;

	if (slot == NULL)
		return NULL;

	cache = *slot;
	if (cache != NULL)
		return cache;

	cache = cache_alloc(socket, class_idx);
	if (cache == NULL)
		return NULL;

	*slot = cache;

	return cache;
}

/*
 * Get-or-create the private per-lcore cache. Returns NULL for callers that
 * have no private cache (secondary process, or no lcore id), which then use
 * the shared cache instead.
 */
static struct fastmem_cache *
cache_get(struct fastmem_socket_state *socket, unsigned int class_idx,
		unsigned int lcore_id)
{
	struct fastmem_cache **slot;
	struct fastmem_cache *cache;

	if (unlikely(!fastmem_is_primary))
		return NULL;

	slot = cache_slot(socket, class_idx, lcore_id);

	if (slot == NULL)
		return NULL;

	cache = *slot;
	if (cache != NULL)
		return cache;

	return cache_create(socket, class_idx, lcore_id);
}

static void *
cache_pop(struct fastmem_cache *cache, struct fastmem_bin *bin)
{
	if (cache->count > 0) {
		cache->alloc_cache_hits++;
		return cache->objs[--cache->count];
	}

	cache->count = bin_alloc_bulk(bin, cache->objs, cache->target, false);
	if (cache->count == 0)
		return NULL;

	cache->alloc_cache_misses++;
	return cache->objs[--cache->count];
}

static void
cache_push(struct fastmem_cache *cache, struct fastmem_bin *bin, void *obj)
{
	unsigned int drain;

	if (cache->count < cache->capacity) {
		cache->free_cache_hits++;
		cache->objs[cache->count++] = obj;
		return;
	}

	cache->free_cache_misses++;

	/*
	 * Drain the oldest (bottom) half to the bin, keep the newest
	 * (top) half for temporal reuse.
	 */
	drain = cache->count - cache->target;
	bin_free_bulk(bin, cache->objs, drain);
	memmove(cache->objs, cache->objs + drain,
		cache->target * sizeof(cache->objs[0]));
	cache->count = cache->target;

	cache->objs[cache->count++] = obj;
}

/* Get-or-create the shared cache; call with shared_cache_lock held. */
static struct fastmem_cache *
shared_cache_get(struct fastmem_socket_state *socket, unsigned int class_idx)
{
	struct fastmem_cache *cache = socket->shared_caches[class_idx];

	if (cache != NULL)
		return cache;

	cache = cache_alloc(socket, class_idx);
	if (cache == NULL)
		return NULL;

	socket->shared_caches[class_idx] = cache;

	return cache;
}

/* Allocate one object via the shared cache, or straight from the bin if the
 * cache cannot be created. */
static void *
shared_alloc_one(struct fastmem_socket_state *socket, unsigned int class_idx)
{
	struct fastmem_bin *bin = &socket->bins[class_idx];
	struct fastmem_cache *cache;
	void *obj;

	rte_spinlock_lock(&socket->shared_cache_lock);

	cache = shared_cache_get(socket, class_idx);
	if (likely(cache != NULL)) {
		obj = cache_pop(cache, bin);
		rte_spinlock_unlock(&socket->shared_cache_lock);
		return obj;
	}

	rte_spinlock_unlock(&socket->shared_cache_lock);

	return bin_alloc_one(bin, true);
}

/* Allocate up to @p n objects via the shared cache; returns the count got. */
static unsigned int
shared_alloc_bulk(struct fastmem_socket_state *socket, unsigned int class_idx,
		void **objs, unsigned int n)
{
	struct fastmem_bin *bin = &socket->bins[class_idx];
	struct fastmem_cache *cache;
	unsigned int got = 0;

	rte_spinlock_lock(&socket->shared_cache_lock);

	cache = shared_cache_get(socket, class_idx);
	if (likely(cache != NULL)) {
		while (got < n) {
			void *obj = cache_pop(cache, bin);

			if (obj == NULL)
				break;
			objs[got++] = obj;
		}
		rte_spinlock_unlock(&socket->shared_cache_lock);
		return got;
	}

	rte_spinlock_unlock(&socket->shared_cache_lock);

	return bin_alloc_bulk(bin, objs, n, true);
}

/* Free one object via the shared cache. */
static void
shared_free_one(struct fastmem_socket_state *socket, unsigned int class_idx,
		void *obj)
{
	struct fastmem_bin *bin = &socket->bins[class_idx];
	struct fastmem_cache *cache;

	rte_spinlock_lock(&socket->shared_cache_lock);

	cache = shared_cache_get(socket, class_idx);
	if (likely(cache != NULL)) {
		cache_push(cache, bin, obj);
		rte_spinlock_unlock(&socket->shared_cache_lock);
		return;
	}

	rte_spinlock_unlock(&socket->shared_cache_lock);

	bin_free_one(bin, obj, true);
}

/* Record an alloc failure against the per-lcore cache, the shared cache, or
 * the bin's no-cache counter, in that order of preference. */
static void
account_alloc_nomem(struct fastmem_socket_state *socket,
		unsigned int class_idx, unsigned int lcore_id)
{
	struct fastmem_cache *cache = cache_get(socket, class_idx, lcore_id);

	if (likely(cache != NULL)) {
		cache->alloc_nomem++;
		return;
	}

	rte_spinlock_lock(&socket->shared_cache_lock);
	cache = shared_cache_get(socket, class_idx);
	if (likely(cache != NULL)) {
		cache->alloc_nomem++;
		rte_spinlock_unlock(&socket->shared_cache_lock);
		return;
	}
	rte_spinlock_unlock(&socket->shared_cache_lock);

	struct fastmem_bin *bin = &socket->bins[class_idx];

	rte_spinlock_lock(&bin->lock);
	bin->nocache_nomem++;
	rte_spinlock_unlock(&bin->lock);
}

static void
socket_release_caches(struct fastmem_socket_state *socket)
{
	unsigned int lcore;
	unsigned int c;

	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		for (c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_cache *cache = socket->caches[lcore][c];
			struct fastmem_slab *cache_slab;

			if (cache == NULL)
				continue;

			if (cache->count > 0) {
				bin_free_bulk(&socket->bins[c],
					cache->objs, cache->count);
				cache->count = 0;
			}

			cache_slab = slab_of(cache);
			bin_free_one(cache_slab->bin, cache, false);

			socket->caches[lcore][c] = NULL;
		}
	}

	for (c = 0; c < FASTMEM_N_CLASSES; c++) {
		struct fastmem_cache *cache = socket->shared_caches[c];
		struct fastmem_slab *cache_slab;

		if (cache == NULL)
			continue;

		if (cache->count > 0) {
			bin_free_bulk(&socket->bins[c],
				cache->objs, cache->count);
			cache->count = 0;
		}

		cache_slab = slab_of(cache);
		bin_free_one(cache_slab->bin, cache, false);

		socket->shared_caches[c] = NULL;
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_init, 24.11)
int
rte_fastmem_init(void)
{
	unsigned int s, c;

	if (fastmem != NULL)
		return -EBUSY;

	fastmem_mz = rte_memzone_reserve_aligned("fastmem_state",
			sizeof(*fastmem), SOCKET_ID_ANY, 0,
			RTE_CACHE_LINE_SIZE);
	if (fastmem_mz == NULL)
		return -ENOMEM;

	fastmem = fastmem_mz->addr;
	fastmem_is_primary = true;
	memset(fastmem, 0, sizeof(*fastmem));

	for (s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		rte_spinlock_init(&socket->lock);
		rte_spinlock_init(&socket->shared_cache_lock);
		socket->memory_limit = SIZE_MAX;

		for (c = 0; c < FASTMEM_N_CLASSES; c++)
			bin_init(&socket->bins[c], c, (int)s);
	}

	return 0;
}

static void
release_socket_caches(struct fastmem_socket_state *socket)
{
	socket_release_caches(socket);
}

static void
release_socket_bins(struct fastmem_socket_state *socket)
{
	unsigned int c;

	for (c = 0; c < FASTMEM_N_CLASSES; c++)
		bin_release(&socket->bins[c], socket);
}

static void
release_socket_memzones(struct fastmem_socket_state *socket)
{
	unsigned int i;

	for (i = 0; i < socket->n_memzones; i++)
		rte_memzone_free(socket->memzones[i]);

	socket->free_head = NULL;
	socket->reserved_bytes = 0;
	socket->n_memzones = 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_deinit, 24.11)
void
rte_fastmem_deinit(void)
{
	unsigned int i;

	if (fastmem == NULL)
		return;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		fastmem = NULL;
		fastmem_mz = NULL;
		return;
	}

	for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
		release_socket_caches(&fastmem->sockets[i]);

	for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
		release_socket_bins(&fastmem->sockets[i]);

	for (i = 0; i < RTE_MAX_NUMA_NODES; i++)
		release_socket_memzones(&fastmem->sockets[i]);

	rte_memzone_free(fastmem_mz);
	fastmem_mz = NULL;
	fastmem = NULL;
}

/* Same resolution order as rte_malloc's malloc_get_numa_socket(). */
static unsigned int
local_socket_id(void)
{
	int sid = (int)rte_socket_id();

	if (likely(sid >= 0 && sid < RTE_MAX_NUMA_NODES))
		return sid;

	sid = (int)rte_lcore_to_socket_id(rte_get_main_lcore());
	if (likely(sid >= 0 && sid < RTE_MAX_NUMA_NODES))
		return sid;

	sid = rte_socket_id_by_idx(0);
	if (likely(sid >= 0 && sid < RTE_MAX_NUMA_NODES))
		return sid;

	return 0;
}

static int
reserve_on_socket(int sid, size_t size)
{
	struct fastmem_socket_state *socket = &fastmem->sockets[sid];
	int rc = 0;

	rte_spinlock_lock(&socket->lock);

	while (socket->reserved_bytes < size) {
		rc = grow_socket(socket, sid);
		if (rc < 0)
			break;
	}

	rte_spinlock_unlock(&socket->lock);

	return rc;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_reserve, 24.11)
int
rte_fastmem_reserve(size_t size, int socket_id)
{
	unsigned int i;
	int rc;

	if (fastmem == NULL)
		return -EINVAL;

	if (socket_id != SOCKET_ID_ANY) {
		if (socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)
			return -EINVAL;
		return reserve_on_socket(socket_id, size);
	}

	rc = reserve_on_socket(local_socket_id(), size);
	if (rc == 0)
		return 0;

	for (i = 0; i < rte_socket_count(); i++) {
		int sid = rte_socket_id_by_idx(i);

		if (sid < 0 || (unsigned int)sid == local_socket_id())
			continue;

		rc = reserve_on_socket(sid, size);
		if (rc == 0)
			return 0;
	}

	return rc;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_set_limit, 24.11)
int
rte_fastmem_set_limit(int socket_id, size_t max_bytes)
{
	if (fastmem == NULL)
		return -EINVAL;

	if (socket_id == SOCKET_ID_ANY) {
		for (unsigned int i = 0; i < RTE_MAX_NUMA_NODES; i++)
			fastmem->sockets[i].memory_limit = max_bytes;
		return 0;
	}

	if (socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)
		return -EINVAL;

	fastmem->sockets[socket_id].memory_limit = max_bytes;
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_get_limit, 24.11)
size_t
rte_fastmem_get_limit(int socket_id)
{
	if (fastmem == NULL || socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)
		return 0;

	return fastmem->sockets[socket_id].memory_limit;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_max_size, 24.11)
size_t
rte_fastmem_max_size(void)
{
	return FASTMEM_MAX_ALLOC_SIZE;
}

static void *
alloc_from_socket(struct fastmem_socket_state *socket,
		unsigned int class_idx, unsigned int lcore_id)
{
	struct fastmem_cache *cache;
	struct fastmem_bin *bin = &socket->bins[class_idx];

	cache = cache_get(socket, class_idx, lcore_id);
	if (likely(cache != NULL))
		return cache_pop(cache, bin);

	return shared_alloc_one(socket, class_idx);
}

static void
do_free(void *ptr)
{
	struct fastmem_slab *slab;
	struct fastmem_bin *bin;
	struct fastmem_socket_state *socket;
	unsigned int lcore_id;
	struct fastmem_cache *cache;

	if (unlikely(!fastmem_assure()))
		return;

	slab = slab_of(ptr);
	bin = slab->bin;
	socket = &fastmem->sockets[bin->socket_id];

	lcore_id = rte_lcore_id();
	cache = cache_get(socket, bin->class_idx, lcore_id);
	if (likely(cache != NULL))
		cache_push(cache, bin, ptr);
	else
		shared_free_one(socket, bin->class_idx, ptr);
}

static int
do_alloc_bulk(void **ptrs, unsigned int n, size_t size, size_t align,
		unsigned int flags, unsigned int lcore_id,
		int socket_id, bool fallback)
{
	unsigned int class_idx;
	struct fastmem_socket_state *socket;
	struct fastmem_cache *cache;
	unsigned int got = 0;

	if (unlikely(!fastmem_assure()))
		return -rte_errno;

	if (unlikely(!normalize_align(&align))) {
		rte_errno = EINVAL;
		return -EINVAL;
	}

	class_idx = size_to_class(size, align);
	if (unlikely(class_idx >= FASTMEM_N_CLASSES)) {
		rte_errno = E2BIG;
		return -E2BIG;
	}

	socket = &fastmem->sockets[socket_id];
	cache = cache_get(socket, class_idx, lcore_id);

	if (likely(cache != NULL)) {
		/* Drain from cache. */
		unsigned int avail = RTE_MIN(cache->count, n);

		cache->count -= avail;
		memcpy(ptrs, &cache->objs[cache->count],
			avail * sizeof(void *));
		got = avail;
		cache->alloc_cache_hits += avail;

		if (got < n) {
			unsigned int need = n - got;
			unsigned int want = RTE_MAX(need, cache->target);
			unsigned int filled;

			if (want <= cache->capacity) {
				/* Refill into cache, give caller their share. */
				filled = bin_alloc_bulk(
					&socket->bins[class_idx],
					cache->objs, want, false);
				if (filled > 0)
					cache->alloc_cache_misses += RTE_MIN(filled, need);
				if (filled >= need) {
					memcpy(ptrs + got,
						cache->objs + filled - need,
						need * sizeof(void *));
					cache->count = filled - need;
					got = n;
				} else {
					memcpy(ptrs + got, cache->objs,
						filled * sizeof(void *));
					got += filled;
					cache->count = 0;
				}
			} else {
				/*
				 * n exceeds cache capacity; pull directly,
				 * but count as cache misses since the caller
				 * has a cache.
				 */
				unsigned int pulled = bin_alloc_bulk(
					&socket->bins[class_idx],
					ptrs + got, need, false);
				if (pulled > 0)
					cache->alloc_cache_misses += pulled;
				got += pulled;
			}
		}
	} else {
		got = shared_alloc_bulk(socket, class_idx, ptrs, n);
	}

	if (unlikely(got < n) && fallback) {
		unsigned int i;

		for (i = 0; i < rte_socket_count() && got < n; i++) {
			int sid = rte_socket_id_by_idx(i);

			if (sid < 0 || sid == socket_id)
				continue;

			socket = &fastmem->sockets[sid];
			cache = cache_get(socket, class_idx, lcore_id);
			if (likely(cache != NULL)) {
				unsigned int avail =
					RTE_MIN(cache->count, n - got);
				cache->count -= avail;
				memcpy(ptrs + got,
					&cache->objs[cache->count],
					avail * sizeof(void *));
				cache->alloc_cache_hits += avail;
				got += avail;
			}
			if (got < n) {
				if (cache != NULL) {
					unsigned int pulled = bin_alloc_bulk(
						&socket->bins[class_idx],
						ptrs + got, n - got, false);
					if (pulled > 0)
						cache->alloc_cache_misses += pulled;
					got += pulled;
				} else {
					got += shared_alloc_bulk(socket,
						class_idx, ptrs + got, n - got);
				}
			}
		}
	}

	if (unlikely(got < n)) {
		/* All-or-nothing: return what we got. */
		unsigned int i;

		for (i = 0; i < got; i++)
			do_free(ptrs[i]);

		account_alloc_nomem(&fastmem->sockets[socket_id], class_idx,
			lcore_id);
		rte_errno = ENOMEM;
		return -ENOMEM;
	}

	if (flags & RTE_FASTMEM_F_ZERO) {
		size_t cs = class_size(class_idx);
		unsigned int i;

		for (i = 0; i < n; i++)
			memset(ptrs[i], 0, cs);
	}

	return 0;
}

static void *
do_alloc(size_t size, size_t align, unsigned int flags,
		unsigned int lcore_id, int socket_id, bool fallback)
{
	unsigned int class_idx;
	void *obj;

	if (unlikely(!fastmem_assure()))
		return NULL;

	if (unlikely(!normalize_align(&align))) {
		rte_errno = EINVAL;
		return NULL;
	}

	class_idx = size_to_class(size, align);
	if (unlikely(class_idx >= FASTMEM_N_CLASSES)) {
		rte_errno = E2BIG;
		return NULL;
	}

	obj = alloc_from_socket(&fastmem->sockets[socket_id],
			class_idx, lcore_id);

	if (likely(obj != NULL))
		goto out;

	if (fallback) {
		unsigned int i;

		for (i = 0; i < rte_socket_count(); i++) {
			int sid = rte_socket_id_by_idx(i);

			if (sid < 0 || sid == socket_id)
				continue;

			obj = alloc_from_socket(&fastmem->sockets[sid],
					class_idx, lcore_id);
			if (obj != NULL)
				goto out;
		}
	}

	account_alloc_nomem(&fastmem->sockets[socket_id], class_idx, lcore_id);
	rte_errno = ENOMEM;
	return NULL;

out:
	if (flags & RTE_FASTMEM_F_ZERO)
		memset(obj, 0, class_size(class_idx));

	return obj;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc, 24.11)
void *
rte_fastmem_alloc(size_t size, size_t align, unsigned int flags)
{
	return do_alloc(size, align, flags, rte_lcore_id(),
			local_socket_id(), false);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc_socket, 24.11)
void *
rte_fastmem_alloc_socket(size_t size, size_t align, unsigned int flags,
		int socket_id)
{
	if (socket_id == SOCKET_ID_ANY)
		return do_alloc(size, align, flags, rte_lcore_id(),
				local_socket_id(), true);

	if (unlikely(socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)) {
		rte_errno = EINVAL;
		return NULL;
	}

	return do_alloc(size, align, flags, rte_lcore_id(), socket_id, false);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_free, 24.11)
void
rte_fastmem_free(void *ptr)
{
	if (unlikely(ptr == NULL))
		return;

	do_free(ptr);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_realloc, 24.11)
void *
rte_fastmem_realloc(void *ptr, size_t size, size_t align)
{
	struct fastmem_slab *slab;
	unsigned int old_class, new_class;
	size_t old_size;
	void *new_ptr;

	if (ptr == NULL)
		return rte_fastmem_alloc(size, align, 0);

	if (size == 0) {
		rte_fastmem_free(ptr);
		return NULL;
	}

	if (unlikely(!normalize_align(&align))) {
		rte_errno = EINVAL;
		return NULL;
	}

	new_class = size_to_class(size, align);
	if (unlikely(new_class >= FASTMEM_N_CLASSES)) {
		rte_errno = E2BIG;
		return NULL;
	}

	slab = slab_of(ptr);
	old_class = slab->bin->class_idx;

	if (new_class == old_class)
		return ptr;

	new_ptr = rte_fastmem_alloc(size, align, 0);
	if (unlikely(new_ptr == NULL))
		return NULL;

	old_size = class_size(old_class);
	memcpy(new_ptr, ptr, RTE_MIN(old_size, size));
	rte_fastmem_free(ptr);

	return new_ptr;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc_bulk, 24.11)
int
rte_fastmem_alloc_bulk(void **ptrs, unsigned int n, size_t size, size_t align,
		unsigned int flags)
{
	return do_alloc_bulk(ptrs, n, size, align, flags,
			rte_lcore_id(), local_socket_id(), false);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc_bulk_socket, 24.11)
int
rte_fastmem_alloc_bulk_socket(void **ptrs, unsigned int n, size_t size,
		size_t align, unsigned int flags, int socket_id)
{
	if (socket_id == SOCKET_ID_ANY)
		return do_alloc_bulk(ptrs, n, size, align, flags,
				rte_lcore_id(), local_socket_id(), true);

	if (unlikely(socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)) {
		rte_errno = EINVAL;
		return -EINVAL;
	}

	return do_alloc_bulk(ptrs, n, size, align, flags,
			rte_lcore_id(), socket_id, false);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_free_bulk, 24.11)
void
rte_fastmem_free_bulk(void **ptrs, unsigned int n)
{
	unsigned int lcore_id;
	struct fastmem_slab *slab;
	struct fastmem_bin *bin;
	struct fastmem_socket_state *socket;
	struct fastmem_cache *cache;
	unsigned int space;
	unsigned int i;

	if (unlikely(n == 0))
		return;

	if (unlikely(!fastmem_assure()))
		return;

	lcore_id = rte_lcore_id();

	/* Fast path: check if first object gives us the bin. */
	slab = slab_of(ptrs[0]);
	bin = slab->bin;
	socket = &fastmem->sockets[bin->socket_id];
	cache = cache_get(socket, bin->class_idx, lcore_id);

	if (unlikely(cache == NULL)) {
		for (i = 0; i < n; i++)
			do_free(ptrs[i]);
		return;
	}

	/*
	 * Try to push all objects into the cache in one memcpy.
	 * If any object belongs to a different bin, fall back to
	 * per-object free for the remainder.
	 */
	space = cache->capacity - cache->count;
	if (likely(n <= space)) {
		/* Verify all same bin (common case). */
		for (i = 1; i < n; i++)
			if (slab_of(ptrs[i])->bin != bin)
				goto slow;
		cache->free_cache_hits += n;
		memcpy(&cache->objs[cache->count], ptrs,
			n * sizeof(void *));
		cache->count += n;
		return;
	}

	/* Would overflow cache — drain first, then push. */
	if (n <= cache->capacity) {
		unsigned int drain;

		for (i = 1; i < n; i++)
			if (slab_of(ptrs[i])->bin != bin)
				goto slow;

		cache->free_cache_misses += n;
		drain = cache->count - cache->target + n;
		if (drain > cache->count)
			drain = cache->count;
		if (drain > 0) {
			bin_free_bulk(bin, cache->objs, drain);
			cache->count -= drain;
			memmove(cache->objs, cache->objs + drain,
				cache->count * sizeof(cache->objs[0]));
		}
		memcpy(&cache->objs[cache->count], ptrs,
			n * sizeof(void *));
		cache->count += n;
		return;
	}

slow:
	for (i = 0; i < n; i++)
		do_free(ptrs[i]);
}

#define fastmem_handle_class_BITS 8

static rte_fastmem_handle_t
fastmem_handle_pack(unsigned int class_idx, int socket_id)
{
	return (uint32_t)class_idx |
		((uint32_t)socket_id << fastmem_handle_class_BITS);
}

static unsigned int
fastmem_handle_class(rte_fastmem_handle_t h)
{
	return h & ((1U << fastmem_handle_class_BITS) - 1);
}

static int
fastmem_handle_socket(rte_fastmem_handle_t h)
{
	return (int)(h >> fastmem_handle_class_BITS);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_hlookup, 24.11)
int
rte_fastmem_hlookup(size_t size, size_t align, int socket_id,
		rte_fastmem_handle_t *handle)
{
	unsigned int class_idx;
	struct fastmem_socket_state *socket;

	if (handle == NULL)
		return -EINVAL;

	if (!normalize_align(&align))
		return -EINVAL;

	if (socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)
		return -EINVAL;

	class_idx = size_to_class(size, align);
	if (class_idx >= FASTMEM_N_CLASSES)
		return -E2BIG;

	/* Pre-create the cache for the calling lcore. */
	socket = &fastmem->sockets[socket_id];
	cache_create(socket, class_idx, rte_lcore_id());

	*handle = fastmem_handle_pack(class_idx, socket_id);
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_halloc, 24.11)
void *
rte_fastmem_halloc(rte_fastmem_handle_t handle, unsigned int flags)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);
	unsigned int lcore_id = rte_lcore_id();
	struct fastmem_socket_state *socket;
	struct fastmem_bin *bin;
	struct fastmem_cache *cache;
	void *obj;

	if (unlikely(!fastmem_assure()))
		return NULL;

	socket = &fastmem->sockets[socket_id];
	bin = &socket->bins[class_idx];

	cache = cache_get(socket, class_idx, lcore_id);
	if (likely(cache != NULL))
		obj = cache_pop(cache, bin);
	else
		obj = shared_alloc_one(socket, class_idx);

	if (unlikely(obj == NULL)) {
		account_alloc_nomem(socket, class_idx, lcore_id);
		rte_errno = ENOMEM;
		return NULL;
	}

	if (flags & RTE_FASTMEM_F_ZERO)
		memset(obj, 0, class_size(class_idx));

	return obj;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_halloc_bulk, 24.11)
int
rte_fastmem_halloc_bulk(rte_fastmem_handle_t handle,
		void **ptrs, unsigned int n, unsigned int flags)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);

	return do_alloc_bulk(ptrs, n, class_size(class_idx),
			RTE_CACHE_LINE_SIZE, flags, rte_lcore_id(),
			socket_id, false);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_hfree, 24.11)
void
rte_fastmem_hfree(rte_fastmem_handle_t handle, void *ptr)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);
	unsigned int lcore_id = rte_lcore_id();
	struct fastmem_socket_state *socket;
	struct fastmem_bin *bin;
	struct fastmem_cache *cache;

	if (unlikely(ptr == NULL))
		return;

	if (unlikely(!fastmem_assure()))
		return;

	socket = &fastmem->sockets[socket_id];
	bin = &socket->bins[class_idx];

	cache = cache_get(socket, class_idx, lcore_id);
	if (likely(cache != NULL))
		cache_push(cache, bin, ptr);
	else
		shared_free_one(socket, class_idx, ptr);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_hfree_bulk, 24.11)
void
rte_fastmem_hfree_bulk(rte_fastmem_handle_t handle,
		void **ptrs, unsigned int n)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);
	struct fastmem_socket_state *socket;
	struct fastmem_bin *bin;
	unsigned int lcore_id;
	struct fastmem_cache *cache;
	unsigned int i;

	if (unlikely(n == 0))
		return;

	if (unlikely(!fastmem_assure()))
		return;

	socket = &fastmem->sockets[socket_id];
	bin = &socket->bins[class_idx];

	lcore_id = rte_lcore_id();
	cache = cache_get(socket, class_idx, lcore_id);

	if (likely(cache != NULL)) {
		for (i = 0; i < n; i++)
			cache_push(cache, bin, ptrs[i]);
	} else {
		for (i = 0; i < n; i++)
			shared_free_one(socket, class_idx, ptrs[i]);
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_virt2iova, 24.11)
rte_iova_t
rte_fastmem_virt2iova(const void *ptr)
{
	struct fastmem_slab *slab;

	if (unlikely(!fastmem_assure()))
		return RTE_BAD_IOVA;

	slab = slab_of((void *)(uintptr_t)ptr);

	return slab->iova_base + ((uintptr_t)ptr - (uintptr_t)slab);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_cache_flush, 24.11)
void
rte_fastmem_cache_flush(void)
{
	unsigned int lcore_id;
	unsigned int s, c;

	if (fastmem == NULL)
		return;

	lcore_id = rte_lcore_id();
	if (lcore_id >= RTE_MAX_LCORE)
		return;

	for (s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		for (c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_cache *cache =
				socket->caches[lcore_id][c];

			if (cache == NULL)
				continue;

			/*
			 * Drain the objects back to the bin, but keep the
			 * cache struct: it holds the lcore's statistics,
			 * which must survive the flush.
			 */
			if (cache->count > 0) {
				bin_free_bulk(&socket->bins[c],
					cache->objs, cache->count);
				cache->count = 0;
			}
		}
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats, 24.11)
int
rte_fastmem_stats(struct rte_fastmem_stats *stats)
{
	if (stats == NULL)
		return -EINVAL;
	if (!fastmem_assure())
		return -ENODEV;

	*stats = (struct rte_fastmem_stats){0};
	stats->n_classes = FASTMEM_N_CLASSES;

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		stats->bytes_backing += socket->reserved_bytes;

		for (unsigned int c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_bin *bin = &socket->bins[c];
			uint64_t class_allocs, class_frees;

			class_allocs = bin->nocache_allocs;
			class_frees = bin->nocache_frees;
			stats->alloc_nomem += bin->nocache_nomem;

			for (unsigned int l = 0; l < RTE_MAX_LCORE; l++) {
				struct fastmem_cache *cache =
					socket->caches[l][c];

				if (cache == NULL)
					continue;

				class_allocs += cache->alloc_cache_hits +
					cache->alloc_cache_misses;
				class_frees += cache->free_cache_hits +
					cache->free_cache_misses;
				stats->alloc_nomem += cache->alloc_nomem;
			}

			struct fastmem_cache *shared = socket->shared_caches[c];

			if (shared != NULL) {
				class_allocs += shared->alloc_cache_hits +
					shared->alloc_cache_misses;
				class_frees += shared->free_cache_hits +
					shared->free_cache_misses;
				stats->alloc_nomem += shared->alloc_nomem;
			}

			stats->alloc_total += class_allocs;
			stats->free_total += class_frees;
			if (class_allocs > class_frees)
				stats->bytes_in_use += class_size(c) *
					(class_allocs - class_frees);
		}
	}

	return 0;
}

static unsigned int
exact_class_idx(size_t sz)
{
	unsigned int log2;

	if (sz < FASTMEM_MIN_SIZE || sz > FASTMEM_MAX_ALLOC_SIZE)
		return FASTMEM_N_CLASSES;
	if ((sz & (sz - 1)) != 0)
		return FASTMEM_N_CLASSES;

	log2 = (unsigned int)rte_ctz64(sz);
	if (log2 < FASTMEM_MIN_CLASS_LOG2 || log2 > FASTMEM_MAX_CLASS_LOG2)
		return FASTMEM_N_CLASSES;

	return log2 - FASTMEM_MIN_CLASS_LOG2;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_class, 24.11)
int
rte_fastmem_stats_class(size_t class_size_arg,
		struct rte_fastmem_class_stats *stats)
{
	unsigned int c;
	uint64_t allocs, frees;

	if (stats == NULL)
		return -EINVAL;
	if (!fastmem_assure())
		return -ENODEV;

	c = exact_class_idx(class_size_arg);
	if (c >= FASTMEM_N_CLASSES)
		return -EINVAL;

	*stats = (struct rte_fastmem_class_stats){0};
	stats->class_size = class_size(c);

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];
		struct fastmem_bin *bin = &socket->bins[c];

		for (unsigned int l = 0; l < RTE_MAX_LCORE; l++) {
			struct fastmem_cache *cache = socket->caches[l][c];

			if (cache == NULL)
				continue;

			stats->alloc_cache_hits += cache->alloc_cache_hits;
			stats->alloc_cache_misses += cache->alloc_cache_misses;
			stats->alloc_nomem += cache->alloc_nomem;
			stats->free_cache_hits += cache->free_cache_hits;
			stats->free_cache_misses += cache->free_cache_misses;
		}

		struct fastmem_cache *shared = socket->shared_caches[c];

		if (shared != NULL) {
			stats->alloc_cache_hits += shared->alloc_cache_hits;
			stats->alloc_cache_misses += shared->alloc_cache_misses;
			stats->alloc_nomem += shared->alloc_nomem;
			stats->free_cache_hits += shared->free_cache_hits;
			stats->free_cache_misses += shared->free_cache_misses;
		}

		/* No-cache fallback traffic; fold into the miss counters. */
		stats->alloc_cache_misses += bin->nocache_allocs;
		stats->free_cache_misses += bin->nocache_frees;
		stats->alloc_nomem += bin->nocache_nomem;

		stats->slab_acquires += bin->slab_acquires;
		stats->slab_releases += bin->slab_releases;
		stats->slabs_partial += bin->slabs_partial;
		stats->slabs_full += bin->slabs_full;
	}

	allocs = stats->alloc_cache_hits + stats->alloc_cache_misses;
	frees = stats->free_cache_hits + stats->free_cache_misses;
	if (allocs > frees)
		stats->in_use = allocs - frees;

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_lcore, 24.11)
int
rte_fastmem_stats_lcore(unsigned int lcore_id,
		struct rte_fastmem_lcore_stats *stats)
{
	if (stats == NULL)
		return -EINVAL;
	if (!fastmem_assure())
		return -ENODEV;
	if (lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	*stats = (struct rte_fastmem_lcore_stats){0};

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		for (unsigned int c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_cache *cache =
				socket->caches[lcore_id][c];

			if (cache == NULL)
				continue;

			stats->alloc_cache_hits += cache->alloc_cache_hits;
			stats->alloc_cache_misses += cache->alloc_cache_misses;
			stats->alloc_nomem += cache->alloc_nomem;
			stats->free_cache_hits += cache->free_cache_hits;
			stats->free_cache_misses += cache->free_cache_misses;
		}
	}

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_lcore_class, 24.11)
int
rte_fastmem_stats_lcore_class(unsigned int lcore_id, size_t class_size_arg,
		struct rte_fastmem_lcore_class_stats *stats)
{
	unsigned int c;

	if (stats == NULL)
		return -EINVAL;
	if (!fastmem_assure())
		return -ENODEV;
	if (lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	c = exact_class_idx(class_size_arg);
	if (c >= FASTMEM_N_CLASSES)
		return -EINVAL;

	*stats = (struct rte_fastmem_lcore_class_stats){0};
	stats->class_size = class_size(c);

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_cache *cache =
			fastmem->sockets[s].caches[lcore_id][c];

		if (cache == NULL)
			continue;

		stats->alloc_cache_hits += cache->alloc_cache_hits;
		stats->alloc_cache_misses += cache->alloc_cache_misses;
		stats->alloc_nomem += cache->alloc_nomem;
		stats->free_cache_hits += cache->free_cache_hits;
		stats->free_cache_misses += cache->free_cache_misses;
	}

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_shared, 24.11)
int
rte_fastmem_stats_shared(struct rte_fastmem_lcore_stats *stats)
{
	if (stats == NULL)
		return -EINVAL;
	if (!fastmem_assure())
		return -ENODEV;

	*stats = (struct rte_fastmem_lcore_stats){0};

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		for (unsigned int c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_cache *cache = socket->shared_caches[c];

			if (cache == NULL)
				continue;

			stats->alloc_cache_hits += cache->alloc_cache_hits;
			stats->alloc_cache_misses += cache->alloc_cache_misses;
			stats->alloc_nomem += cache->alloc_nomem;
			stats->free_cache_hits += cache->free_cache_hits;
			stats->free_cache_misses += cache->free_cache_misses;
		}
	}

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_shared_class, 24.11)
int
rte_fastmem_stats_shared_class(size_t class_size_arg,
		struct rte_fastmem_lcore_class_stats *stats)
{
	unsigned int c;

	if (stats == NULL)
		return -EINVAL;
	if (!fastmem_assure())
		return -ENODEV;

	c = exact_class_idx(class_size_arg);
	if (c >= FASTMEM_N_CLASSES)
		return -EINVAL;

	*stats = (struct rte_fastmem_lcore_class_stats){0};
	stats->class_size = class_size(c);

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_cache *cache =
			fastmem->sockets[s].shared_caches[c];

		if (cache == NULL)
			continue;

		stats->alloc_cache_hits += cache->alloc_cache_hits;
		stats->alloc_cache_misses += cache->alloc_cache_misses;
		stats->alloc_nomem += cache->alloc_nomem;
		stats->free_cache_hits += cache->free_cache_hits;
		stats->free_cache_misses += cache->free_cache_misses;
	}

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_reset, 24.11)
void
rte_fastmem_stats_reset(void)
{
	if (fastmem == NULL)
		return;

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		for (unsigned int c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_bin *bin = &socket->bins[c];

			rte_spinlock_lock(&bin->lock);
			bin->slab_acquires = 0;
			bin->slab_releases = 0;
			bin->nocache_allocs = 0;
			bin->nocache_frees = 0;
			bin->nocache_nomem = 0;
			rte_spinlock_unlock(&bin->lock);

			for (unsigned int l = 0; l < RTE_MAX_LCORE; l++) {
				struct fastmem_cache *cache =
					socket->caches[l][c];
				if (cache == NULL)
					continue;
				cache->alloc_cache_hits = 0;
				cache->alloc_cache_misses = 0;
				cache->alloc_nomem = 0;
				cache->free_cache_hits = 0;
				cache->free_cache_misses = 0;
			}

			rte_spinlock_lock(&socket->shared_cache_lock);
			struct fastmem_cache *shared = socket->shared_caches[c];
			if (shared != NULL) {
				shared->alloc_cache_hits = 0;
				shared->alloc_cache_misses = 0;
				shared->alloc_nomem = 0;
				shared->free_cache_hits = 0;
				shared->free_cache_misses = 0;
			}
			rte_spinlock_unlock(&socket->shared_cache_lock);
		}
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_classes, 24.11)
unsigned int
rte_fastmem_classes(size_t *sizes)
{
	if (sizes != NULL)
		for (unsigned int i = 0; i < FASTMEM_N_CLASSES; i++)
			sizes[i] = class_size(i);
	return FASTMEM_N_CLASSES;
}

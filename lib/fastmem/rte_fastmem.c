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
};

/* Per-(lcore, class, socket) bounded LIFO of free object pointers. */
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
};

struct fastmem {
	struct fastmem_socket_state sockets[RTE_MAX_NUMA_NODES];
};

static struct fastmem *fastmem;
static const struct rte_memzone *fastmem_mz;
static bool fastmem_is_primary; /* cached; avoids function call on hot path */

static struct fastmem *
fastmem_get(void)
{
	const struct rte_memzone *mz;

	if (likely(fastmem != NULL))
		return fastmem;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		rte_errno = ENODEV;
		return NULL;
	}

	mz = rte_memzone_lookup("fastmem_state");
	if (mz == NULL) {
		rte_errno = ENODEV;
		return NULL;
	}

	fastmem_mz = mz;
	fastmem = mz->addr;
	return fastmem;
}

static inline unsigned int
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

static inline size_t
class_size(unsigned int class_idx)
{
	return (size_t)1 << (class_idx + FASTMEM_MIN_CLASS_LOG2);
}

static_assert(sizeof(struct fastmem_slab) == FASTMEM_SLAB_HEADER_SIZE,
	"fastmem slab header must fit in exactly one cache line");
static_assert(sizeof(struct fastmem_slab) <= FASTMEM_SLAB_SIZE,
	"slab header larger than a slab makes no sense");

static __rte_always_inline struct fastmem_slab *
slab_of(void *obj)
{
	return (struct fastmem_slab *)
		((uintptr_t)obj & ~(uintptr_t)FASTMEM_SLAB_MASK);
}

static inline size_t
slab_slot0_offset(size_t class_size)
{
	return class_size < FASTMEM_SLAB_HEADER_SIZE ?
		FASTMEM_SLAB_HEADER_SIZE : class_size;
}

static inline uint32_t
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

static void *
bin_alloc_one(struct fastmem_bin *bin)
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

	rte_spinlock_unlock(&bin->lock);

	return obj;
}

static unsigned int
bin_alloc_bulk(struct fastmem_bin *bin, void **objs, unsigned int n)
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

	rte_spinlock_unlock(&bin->lock);

	return got;
}

static void
bin_free_one(struct fastmem_bin *bin, void *obj)
{
	unsigned int n_release;
	struct fastmem_slab *slab_to_release = NULL;
	struct fastmem_socket_state *socket;

	rte_spinlock_lock(&bin->lock);
	n_release = bin_push_locked(bin, &obj, 1, &slab_to_release);
	rte_spinlock_unlock(&bin->lock);

	if (n_release > 0) {
		socket = &fastmem->sockets[bin->socket_id];
		slab_release(socket, slab_to_release);
	}
}

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

static inline unsigned int
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

static inline struct fastmem_cache **
cache_slot(struct fastmem_socket_state *socket, unsigned int class_idx,
		unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE)
		return NULL;
	return &socket->caches[lcore_id][class_idx];
}

static struct fastmem_cache *
cache_create(struct fastmem_socket_state *socket,
		unsigned int class_idx, unsigned int lcore_id)
{
	struct fastmem_cache **slot = cache_slot(socket, class_idx, lcore_id);
	struct fastmem_cache *cache;
	unsigned int capacity;
	size_t cache_size;
	unsigned int cache_class;
	unsigned int own_socket;
	struct fastmem_socket_state *alloc_socket;

	if (slot == NULL)
		return NULL;

	cache = *slot;
	if (cache != NULL)
		return cache;

	capacity = cache_capacity(class_idx);
	cache_size = sizeof(*cache) + capacity * sizeof(void *);

	/*
	 * Allocate the cache struct from fastmem on the calling
	 * lcore's socket (NUMA-local to the writer). Bypasses the
	 * cache layer to avoid recursion.
	 */
	cache_class = size_to_class(cache_size, RTE_CACHE_LINE_SIZE);
	own_socket = rte_socket_id();

	if (cache_class >= FASTMEM_N_CLASSES) {
		FASTMEM_LOG(ERR,
			"cache size %zu exceeds max size class",
			cache_size);
		return NULL;
	}

	if (own_socket >= RTE_MAX_NUMA_NODES)
		own_socket = (unsigned int)socket->bins[0].socket_id;

	alloc_socket = &fastmem->sockets[own_socket];

	cache = bin_alloc_one(&alloc_socket->bins[cache_class]);
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

	*slot = cache;

	return cache;
}

static __rte_always_inline struct fastmem_cache *
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

static __rte_always_inline void *
cache_pop(struct fastmem_cache *cache, struct fastmem_bin *bin)
{
	if (cache->count > 0) {
		cache->alloc_cache_hits++;
		return cache->objs[--cache->count];
	}

	cache->count = bin_alloc_bulk(bin, cache->objs, cache->target);
	if (cache->count == 0)
		return NULL;

	cache->alloc_cache_misses++;
	return cache->objs[--cache->count];
}

static __rte_always_inline void
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
	 * Drain the oldest (bottom) half to the bin, keeping the
	 * newest (top) half for temporal reuse.
	 */
	drain = cache->count - cache->target;
	bin_free_bulk(bin, cache->objs, drain);
	memmove(cache->objs, cache->objs + drain,
		cache->target * sizeof(cache->objs[0]));
	cache->count = cache->target;

	cache->objs[cache->count++] = obj;
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
			bin_free_one(cache_slab->bin, cache);

			socket->caches[lcore][c] = NULL;
		}
	}
}

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_init, 24.11)
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

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_deinit, 24.11)
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
static __rte_always_inline unsigned int
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

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_reserve, 24.11)
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

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_set_limit, 24.11)
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

size_t
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_get_limit, 24.11)
rte_fastmem_get_limit(int socket_id)
{
	if (fastmem == NULL || socket_id < 0 || socket_id >= RTE_MAX_NUMA_NODES)
		return 0;

	return fastmem->sockets[socket_id].memory_limit;
}

size_t
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_max_size, 24.11)
rte_fastmem_max_size(void)
{
	return FASTMEM_MAX_ALLOC_SIZE;
}

static __rte_always_inline void *
alloc_from_socket(struct fastmem_socket_state *socket,
		unsigned int class_idx, unsigned int lcore_id)
{
	struct fastmem_cache *cache;

	cache = cache_get(socket, class_idx, lcore_id);
	if (likely(cache != NULL))
		return cache_pop(cache, &socket->bins[class_idx]);
	return bin_alloc_one(&socket->bins[class_idx]);
}

static __rte_always_inline void
do_free(void *ptr)
{
	struct fastmem_slab *slab;
	struct fastmem_bin *bin;
	struct fastmem_socket_state *socket;
	unsigned int lcore_id;
	struct fastmem_cache *cache;

	slab = slab_of(ptr);
	bin = slab->bin;
	socket = &fastmem->sockets[bin->socket_id];

	lcore_id = rte_lcore_id();
	cache = cache_get(socket, bin->class_idx, lcore_id);
	if (likely(cache != NULL))
		cache_push(cache, bin, ptr);
	else
		bin_free_one(bin, ptr);
}

static __rte_always_inline int
do_alloc_bulk(void **ptrs, unsigned int n, size_t size, size_t align,
		unsigned int flags, unsigned int lcore_id,
		int socket_id, bool fallback)
{
	unsigned int class_idx;
	struct fastmem_socket_state *socket;
	struct fastmem_cache *cache;
	unsigned int got = 0;

	if (unlikely(fastmem_get() == NULL))
		return -rte_errno;

	if (align == 0)
		align = RTE_CACHE_LINE_SIZE;
	else if (unlikely((align & (align - 1)) != 0)) {
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
					cache->objs, want);
				if (filled > 0) {
					cache->alloc_cache_misses += RTE_MIN(filled, need);
				}
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
				/* n exceeds cache capacity; pull directly. */
				unsigned int direct = bin_alloc_bulk(
					&socket->bins[class_idx],
					ptrs + got, need);
				if (direct > 0)
					cache->alloc_cache_misses += direct;
				got += direct;
			}
		}
	} else {
		got = bin_alloc_bulk(&socket->bins[class_idx], ptrs, n);
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
				unsigned int direct = bin_alloc_bulk(
					&socket->bins[class_idx],
					ptrs + got, n - got);
				if (direct > 0 && cache != NULL)
					cache->alloc_cache_misses += direct;
				got += direct;
			}
		}
	}

	if (unlikely(got < n)) {
		/* All-or-nothing: return what we got. */
		struct fastmem_cache **slot;
		unsigned int i;

		for (i = 0; i < got; i++)
			do_free(ptrs[i]);

		slot = cache_slot(
			&fastmem->sockets[socket_id], class_idx,
			lcore_id);
		if (slot != NULL && *slot != NULL)
			(*slot)->alloc_nomem++;
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

static __rte_always_inline void *
do_alloc(size_t size, size_t align, unsigned int flags,
		unsigned int lcore_id, int socket_id, bool fallback)
{
	unsigned int class_idx;
	struct fastmem_cache **slot;
	void *obj;

	if (unlikely(fastmem_get() == NULL))
		return NULL;

	if (align == 0)
		align = RTE_CACHE_LINE_SIZE;
	else if (unlikely((align & (align - 1)) != 0)) {
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

	slot = cache_slot(
		&fastmem->sockets[socket_id], class_idx, lcore_id);
	if (slot != NULL && *slot != NULL)
		(*slot)->alloc_nomem++;
	rte_errno = ENOMEM;
	return NULL;

out:
	if (flags & RTE_FASTMEM_F_ZERO)
		memset(obj, 0, class_size(class_idx));

	return obj;
}

void *
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc, 24.11)
rte_fastmem_alloc(size_t size, size_t align, unsigned int flags)
{
	return do_alloc(size, align, flags, rte_lcore_id(),
			local_socket_id(), false);
}

void *
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc_socket, 24.11)
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

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_free, 24.11)
rte_fastmem_free(void *ptr)
{
	if (unlikely(ptr == NULL))
		return;

	do_free(ptr);
}

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc_bulk, 24.11)
rte_fastmem_alloc_bulk(void **ptrs, unsigned int n, size_t size, size_t align,
		unsigned int flags)
{
	return do_alloc_bulk(ptrs, n, size, align, flags,
			rte_lcore_id(), local_socket_id(), false);
}

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_alloc_bulk_socket, 24.11)
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

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_free_bulk, 24.11)
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
		for (i = 1; i < n; i++) {
			if (slab_of(ptrs[i])->bin != bin)
				goto slow;
		}
		cache->free_cache_hits += n;
		memcpy(&cache->objs[cache->count], ptrs,
			n * sizeof(void *));
		cache->count += n;
		return;
	}

	/* Would overflow cache — drain first, then push. */
	if (n <= cache->capacity) {
		unsigned int drain;

		for (i = 1; i < n; i++) {
			if (slab_of(ptrs[i])->bin != bin)
				goto slow;
		}

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

static inline rte_fastmem_handle_t
fastmem_handle_pack(unsigned int class_idx, int socket_id)
{
	return (uint32_t)class_idx |
		((uint32_t)socket_id << fastmem_handle_class_BITS);
}

static inline unsigned int
fastmem_handle_class(rte_fastmem_handle_t h)
{
	return h & ((1U << fastmem_handle_class_BITS) - 1);
}

static inline int
fastmem_handle_socket(rte_fastmem_handle_t h)
{
	return (int)(h >> fastmem_handle_class_BITS);
}

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_hlookup, 24.11)
rte_fastmem_hlookup(size_t size, size_t align, int socket_id,
		rte_fastmem_handle_t *handle)
{
	unsigned int class_idx;
	struct fastmem_socket_state *socket;

	if (handle == NULL)
		return -EINVAL;

	if (align == 0)
		align = RTE_CACHE_LINE_SIZE;
	else if ((align & (align - 1)) != 0)
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

void *
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_halloc, 24.11)
rte_fastmem_halloc(rte_fastmem_handle_t handle, unsigned int flags)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);
	unsigned int lcore_id = rte_lcore_id();
	struct fastmem_socket_state *socket = &fastmem->sockets[socket_id];
	struct fastmem_bin *bin = &socket->bins[class_idx];
	struct fastmem_cache *cache;
	void *obj;

	RTE_ASSERT(fastmem != NULL);
	RTE_ASSERT(lcore_id < RTE_MAX_LCORE);

	cache = socket->caches[lcore_id][class_idx];
	RTE_ASSERT(cache != NULL);

	obj = cache_pop(cache, bin);
	if (unlikely(obj == NULL)) {
		rte_errno = ENOMEM;
		return NULL;
	}

	if (flags & RTE_FASTMEM_F_ZERO)
		memset(obj, 0, class_size(class_idx));

	return obj;
}

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_halloc_bulk, 24.11)
rte_fastmem_halloc_bulk(rte_fastmem_handle_t handle,
		void **ptrs, unsigned int n, unsigned int flags)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);

	return do_alloc_bulk(ptrs, n, class_size(class_idx),
			RTE_CACHE_LINE_SIZE, flags, rte_lcore_id(),
			socket_id, false);
}

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_hfree, 24.11)
rte_fastmem_hfree(rte_fastmem_handle_t handle, void *ptr)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);
	struct fastmem_socket_state *socket = &fastmem->sockets[socket_id];
	struct fastmem_bin *bin = &socket->bins[class_idx];
	unsigned int lcore_id = rte_lcore_id();
	struct fastmem_cache *cache;

	if (unlikely(ptr == NULL))
		return;

	RTE_ASSERT(lcore_id < RTE_MAX_LCORE);

	cache = socket->caches[lcore_id][class_idx];
	RTE_ASSERT(cache != NULL);

	cache_push(cache, bin, ptr);
}

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_hfree_bulk, 24.11)
rte_fastmem_hfree_bulk(rte_fastmem_handle_t handle,
		void **ptrs, unsigned int n)
{
	unsigned int class_idx = fastmem_handle_class(handle);
	int socket_id = fastmem_handle_socket(handle);
	struct fastmem_socket_state *socket = &fastmem->sockets[socket_id];
	struct fastmem_bin *bin = &socket->bins[class_idx];
	unsigned int lcore_id;
	struct fastmem_cache *cache;
	unsigned int i;

	if (unlikely(n == 0))
		return;

	lcore_id = rte_lcore_id();
	cache = cache_get(socket, class_idx, lcore_id);

	if (likely(cache != NULL)) {
		for (i = 0; i < n; i++)
			cache_push(cache, bin, ptrs[i]);
	} else {
		for (i = 0; i < n; i++)
			bin_free_one(bin, ptrs[i]);
	}
}

rte_iova_t
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_virt2iova, 24.11)
rte_fastmem_virt2iova(const void *ptr)
{
	struct fastmem_slab *slab;

	RTE_ASSERT(fastmem != NULL);

	slab = slab_of((void *)(uintptr_t)ptr);

	return slab->iova_base + ((uintptr_t)ptr - (uintptr_t)slab);
}

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_cache_flush, 24.11)
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
			struct fastmem_slab *cache_slab;

			if (cache == NULL)
				continue;

			if (cache->count > 0) {
				bin_free_bulk(&socket->bins[c],
					cache->objs, cache->count);
				cache->count = 0;
			}

			cache_slab = slab_of(cache);
			bin_free_one(cache_slab->bin, cache);

			socket->caches[lcore_id][c] = NULL;
		}
	}
}

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats, 24.11)
rte_fastmem_stats(struct rte_fastmem_stats *stats)
{
	if (stats == NULL || fastmem == NULL)
		return -EINVAL;

	*stats = (struct rte_fastmem_stats){0};
	stats->n_classes = FASTMEM_N_CLASSES;

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		stats->bytes_backing += socket->reserved_bytes;

		for (unsigned int c = 0; c < FASTMEM_N_CLASSES; c++) {
			uint64_t class_allocs = 0, class_frees = 0;

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
			stats->alloc_total += class_allocs;
			stats->free_total += class_frees;
			if (class_allocs > class_frees)
				stats->bytes_in_use += class_size(c) *
					(class_allocs - class_frees);
		}
	}

	return 0;
}

static inline unsigned int
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

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_class, 24.11)
rte_fastmem_stats_class(size_t class_size_arg,
		struct rte_fastmem_class_stats *stats)
{
	unsigned int c;
	uint64_t allocs, frees;

	if (stats == NULL || fastmem == NULL)
		return -EINVAL;

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

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_lcore, 24.11)
rte_fastmem_stats_lcore(unsigned int lcore_id,
		struct rte_fastmem_lcore_stats *stats)
{
	if (stats == NULL || fastmem == NULL)
		return -EINVAL;
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

int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_lcore_class, 24.11)
rte_fastmem_stats_lcore_class(unsigned int lcore_id, size_t class_size_arg,
		struct rte_fastmem_lcore_class_stats *stats)
{
	unsigned int c;

	if (stats == NULL || fastmem == NULL)
		return -EINVAL;
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

void
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_stats_reset, 24.11)
rte_fastmem_stats_reset(void)
{
	if (fastmem == NULL)
		return;

	for (unsigned int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
		struct fastmem_socket_state *socket = &fastmem->sockets[s];

		for (unsigned int c = 0; c < FASTMEM_N_CLASSES; c++) {
			struct fastmem_bin *bin = &socket->bins[c];

			bin->slab_acquires = 0;
			bin->slab_releases = 0;

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
		}
	}
}

unsigned int
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fastmem_classes, 24.11)
rte_fastmem_classes(size_t *sizes)
{
	if (sizes != NULL)
		for (unsigned int i = 0; i < FASTMEM_N_CLASSES; i++)
			sizes[i] = class_size(i);
	return FASTMEM_N_CLASSES;
}

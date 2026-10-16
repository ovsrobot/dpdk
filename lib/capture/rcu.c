/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Grace period for the capture callbacks.
 *
 * A callback loads cbs->cap and uses it for one burst. Teardown clears
 * cbs->cap and then wants to free the capture, but must wait for any callback
 * still using the pointer it loaded a moment ago. Being on the datapath, the
 * callbacks cannot afford a lock or an atomic to announce that they are busy.
 *
 * So a reader announces itself with plain stores to a slot nobody else
 * writes: the current token on entry, zero on exit. To wait, capture_rcu_sync
 * bumps the token and then watches every slot until each reads either zero,
 * meaning idle, or a token at least as new as the bump, meaning the reader
 * started afterwards and so cannot be holding the old pointer. Once it
 * returns, every callback that could hold the old pointer has finished.
 *
 * Taking the token as 4 before the bump and 5 after:
 *
 *                       clear cbs->cap    token 4->5          free
 *                              |              |                |
 *   writer  ------------------>+--------------++--------------->
 *                                              |<--- wait --->|
 *
 *   reader A  --[ctr=4 ....uses cap.... ctr=0]----------------->
 *                            waited for: ctr=4 is older than 5
 *
 *   reader B  ------------------------[ctr=0]----------------->
 *                            ignored: idle when sync looked
 *
 *   reader C  ---------------------------------[ctr=5 ....]---->
 *                            ignored: ctr=5 is not older than 5,
 *                            so it loaded cap after the clear
 *
 * A is the only one the writer waits for. B holds nothing, and C started late
 * enough that it must have seen the cleared pointer.
 *
 * Slots are indexed by lcore id, and sync scans all of them rather than a
 * list of live readers, so a thread that registers with EAL during a grace
 * period needs no special handling: its slot was already being watched.
 *
 * Plain stores alone would not be enough, because the CPU may hoist the
 * reader's loads above the store that marks it busy. The writer would then
 * see an idle slot belonging to a reader that is about to use the old
 * pointer. Normally the reader prevents that with a store-load fence, which
 * is exactly the cost this is trying to avoid; instead the writer asks the OS
 * to run a barrier on every CPU running a thread of the process. The ordering
 * is the same and the cost lands on teardown, which is rare. liburcu calls
 * this its "memb" flavor, where fixed slots take the place of its registry of
 * reader threads.
 *
 * Without that OS barrier the library registers no telemetry commands, so no
 * capture starts and no reader runs. Readers never fence themselves.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_pause.h>
#include <rte_stdatomic.h>

#include "private.h"
#include "rcu.h"

struct capture_rcu capture_rcu = {
	.token = 1,
};

/*
 * OS backends. Each provides:
 *   capture_rcu_mb_init()  register once, return false if unavailable
 *   capture_rcu_mb_os()    full barrier on every CPU running a thread of
 *                          this process, return false on failure
 *
 * MEMBARRIER_CMD_PRIVATE_EXPEDITED and its registration need Linux 4.14,
 * well below the oldest kernel DPDK supports, so no runtime query is done.
 * Windows is not supported yet but has an equivalent in
 * FlushProcessWriteBuffers(), so the backend is kept here for when it is.
 */
#if defined(RTE_EXEC_ENV_LINUX)

#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <unistd.h>

static bool
capture_rcu_mb_register(void)
{
	return syscall(SYS_membarrier,
		       MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) == 0;
}

static bool
capture_rcu_mb_init(void)
{
	return capture_rcu_mb_register();
}

static bool
capture_rcu_mb_os(void)
{
	if (syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0)
		return true;

	/*
	 * Registration is per memory map, and fork() gives the child a fresh
	 * one, so an application that daemonizes after the constructor ran
	 * lands here. Register this map and try once more.
	 */
	if (errno == EPERM && capture_rcu_mb_register())
		return syscall(SYS_membarrier,
			       MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0;
	return false;
}

#elif defined(RTE_EXEC_ENV_FREEBSD)

/* FreeBSD 14.1 and later, same command set as Linux */
#include <sys/membarrier.h>

static bool
capture_rcu_mb_register(void)
{
	return membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) == 0;
}

static bool
capture_rcu_mb_init(void)
{
	return capture_rcu_mb_register();
}

static bool
capture_rcu_mb_os(void)
{
	if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0)
		return true;

	/* see the Linux comment: a fresh memory map is not registered */
	if (errno == EPERM && capture_rcu_mb_register())
		return membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0;
	return false;
}

#elif defined(RTE_EXEC_ENV_WINDOWS)

#include <rte_windows.h>

/* always available, no registration needed, process scope */
static bool
capture_rcu_mb_init(void)
{
	return true;
}

static bool
capture_rcu_mb_os(void)
{
	FlushProcessWriteBuffers();
	return true;
}

#else

static bool
capture_rcu_mb_init(void)
{
	return false;
}

static bool
capture_rcu_mb_os(void)
{
	return false;
}

#endif

/* Full barrier on every CPU running a thread of this process. */
static void
capture_rcu_mb_all(void)
{
	/* order this thread's own prior stores first */
	rte_atomic_thread_fence(rte_memory_order_seq_cst);

	if (likely(capture_rcu_mb_os()))
		return;

	/*
	 * Readers only compiler-barrier, so this is the only thing ordering
	 * their slot store ahead of their loads. It worked at startup or the
	 * library would not have registered, so a failure here means the
	 * environment changed underneath us.
	 *
	 * Rather than panic, wait instead. The reorderings the barrier would
	 * have prevented, a slot store still sitting in a store buffer or a
	 * load hoisted above it, resolve in nanoseconds, and this sleep is far
	 * longer. A reader still inside a burst is waited for by the slot scan
	 * in capture_rcu_sync(), not by this.
	 */
	static bool once;
	if (!once) {
		once = true;
		CAPTURE_LOG(NOTICE, "membarrier failed (%s), sleeping instead",
			    strerror(errno));
	}
	rte_delay_us_sleep(CAPTURE_RCU_MB_FAIL_US);
}

void
capture_rcu_sync(void)
{
	uint64_t t;
	unsigned int i;

	/*
	 * Readers that already hold the old pointer have their slot store
	 * visible after this; readers that store later load the new state.
	 */
	capture_rcu_mb_all();

	t = rte_atomic_fetch_add_explicit(&capture_rcu.token, 1,
					  rte_memory_order_seq_cst) + 1;

	for (i = 0; i < CAPTURE_RCU_SLOTS; i++) {
		const struct capture_rcu_reader *r = &capture_rcu.reader[i];
		uint64_t c;

		for (;;) {
			c = rte_atomic_load_explicit(&r->ctr, rte_memory_order_acquire);
			/* idle, or entered after the token bump */
			if (c == 0 || c >= t)
				break;
			rte_pause();
		}
	}

	/* readers' last loads of the old object complete before the caller frees */
	capture_rcu_mb_all();
}

/*
 * Prove the barrier works here before anything can rely on it: the syscall
 * exists, registration took, and nothing is filtering it.
 */
bool
capture_rcu_init(void)
{
	return capture_rcu_mb_init() && capture_rcu_mb_os();
}

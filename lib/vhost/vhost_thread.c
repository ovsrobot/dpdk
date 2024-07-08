#include <rte_rwlock.h>

#include "vhost_thread.h"

static rte_rwlock_t vhost_thread_lock = RTE_RWLOCK_INITIALIZER;

void
vhost_thread_read_lock(void)
{
	rte_rwlock_read_lock(&vhost_thread_lock);
}

void
vhost_thread_read_unlock(void)
{
	rte_rwlock_read_unlock(&vhost_thread_lock);
}

void
vhost_thread_write_lock(void)
{
	rte_rwlock_write_lock(&vhost_thread_lock);
}

void
vhost_thread_write_unlock(void)
{
	rte_rwlock_write_unlock(&vhost_thread_lock);
}

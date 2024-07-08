#ifndef _VHOST_THREAD_H_
#define _VHOST_THREAD_H_

void vhost_thread_read_lock(void);

void vhost_thread_read_unlock(void);

void vhost_thread_write_lock(void);

void vhost_thread_write_unlock(void);

#endif

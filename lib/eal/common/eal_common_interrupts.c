/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <stdlib.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_interrupts.h>

/* Macros to check for valid port */
#define CHECK_VALID_INTR_HANDLE(intr_handle) do { \
	if (intr_handle == NULL) { \
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n"); \
		rte_errno = EINVAL; \
		goto fail; \
	} \
} while (0)

#define RTE_INTR_INSTANCE_KNOWN_FLAGS (		\
	RTE_INTR_INSTANCE_F_SHARED	|	\
	RTE_INTR_INSTANCE_F_UNSHARED)

#define IS_RTE_MEMORY(intr_handle)		\
		!!(intr_handle->alloc_flag & RTE_INTR_INSTANCE_F_SHARED)

struct rte_intr_handle {
	RTE_STD_C11
	union {
		struct {
			/** VFIO/UIO cfg device file descriptor */
			int dev_fd;
			int fd;	/**< interrupt event file descriptor */
		};
		void *windows_handle; /**< device driver handle */
	};
	uint32_t alloc_flag;	/** Interrupt instance alloc flag */
	enum rte_intr_handle_type type;  /**< handle type */
	uint32_t max_intr;            /**< max interrupt requested */
	uint32_t nb_efd;              /**< number of available efd(event fd) */
	uint8_t efd_counter_size;     /**< size of efd counter, used for vdev */
	uint16_t nb_intr;
		/**< Max vector count, default RTE_MAX_RXTX_INTR_VEC_ID */
	int *efds;  /**< intr vectors/efds mapping */
	struct rte_epoll_event *elist; /**< intr vector epoll event */
	uint16_t vec_list_size;
	int *intr_vec;                 /**< intr vector number array */
};

struct rte_intr_handle *rte_intr_instance_alloc(uint32_t flags)
{
	struct rte_intr_handle *intr_handle;
	bool is_rte_memory;

	/* Check the flag passed by user, it should be part of the
	 * defined flags.
	 */
	if ((flags & (flags - 1)) ||
	    (flags & ~RTE_INTR_INSTANCE_KNOWN_FLAGS) != 0) {
		RTE_LOG(ERR, EAL, "Invalid alloc flag passed %x\n", flags);
		rte_errno = EINVAL;
		return NULL;
	}

	is_rte_memory = (flags & RTE_INTR_INSTANCE_F_SHARED) != 0;
	if (is_rte_memory == true)
		intr_handle = rte_zmalloc(NULL, sizeof(*intr_handle), 0);
	else
		intr_handle = calloc(1, sizeof(*intr_handle));
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Fail to allocate intr_handle\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	if (is_rte_memory)
		intr_handle->efds = rte_zmalloc(NULL,
						RTE_MAX_RXTX_INTR_VEC_ID *
						sizeof(uint32_t), 0);
	else
		intr_handle->efds = calloc(RTE_MAX_RXTX_INTR_VEC_ID,
					   sizeof(uint32_t));
	if (!intr_handle->efds) {
		RTE_LOG(ERR, EAL, "Fail to allocate event fd list\n");
		rte_errno = ENOMEM;
		goto fail;
	}

	if (is_rte_memory)
		intr_handle->elist =
			rte_zmalloc(NULL, RTE_MAX_RXTX_INTR_VEC_ID *
				    sizeof(struct rte_epoll_event), 0);
	else
		intr_handle->elist = calloc(RTE_MAX_RXTX_INTR_VEC_ID,
					    sizeof(struct rte_epoll_event));
	if (!intr_handle->elist) {
		RTE_LOG(ERR, EAL, "fail to allocate event fd list\n");
		rte_errno = ENOMEM;
		goto fail;
	}

	intr_handle->nb_intr = RTE_MAX_RXTX_INTR_VEC_ID;
	intr_handle->alloc_flag = flags;

	return intr_handle;
fail:
	if (is_rte_memory) {
		rte_free(intr_handle->efds);
		rte_free(intr_handle);
	} else {
		free(intr_handle->efds);
		free(intr_handle);
	}
	return NULL;
}

int rte_intr_instance_copy(struct rte_intr_handle *intr_handle,
			   const struct rte_intr_handle *src)
{
	struct rte_epoll_event *tmp_elist;
	int *tmp_efds;

	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (src == NULL) {
		RTE_LOG(ERR, EAL, "Source interrupt instance unallocated\n");
		rte_errno = EINVAL;
		goto fail;
	}

	intr_handle->fd = src->fd;
	intr_handle->dev_fd = src->dev_fd;
	intr_handle->type = src->type;
	intr_handle->alloc_flag = src->alloc_flag;
	intr_handle->max_intr = src->max_intr;
	intr_handle->nb_efd = src->nb_efd;
	intr_handle->efd_counter_size = src->efd_counter_size;

	if (intr_handle->nb_intr != src->nb_intr) {
		if (IS_RTE_MEMORY(src))
			tmp_efds = rte_realloc(intr_handle->efds, src->nb_intr *
					       sizeof(uint32_t), 0);
		else
			tmp_efds = realloc(intr_handle->efds, src->nb_intr *
					   sizeof(uint32_t));
		if (tmp_efds == NULL) {
			RTE_LOG(ERR, EAL, "Failed to realloc the efds list");
			rte_errno = ENOMEM;
			goto fail;
		}

		if (IS_RTE_MEMORY(src))
			tmp_elist = rte_realloc(intr_handle->elist,
						src->nb_intr *
						sizeof(struct rte_epoll_event),
						0);
		else
			tmp_elist = realloc(intr_handle->elist,	src->nb_intr *
					    sizeof(struct rte_epoll_event));
		if (tmp_elist == NULL) {
			RTE_LOG(ERR, EAL, "Failed to realloc the event list");
			rte_errno = ENOMEM;
			goto up_efds;
		}

		intr_handle->efds = tmp_efds;
		intr_handle->elist = tmp_elist;
		intr_handle->nb_intr = src->nb_intr;
	}

	memcpy(intr_handle->efds, src->efds, src->nb_intr);
	memcpy(intr_handle->elist, src->elist, src->nb_intr);

	return 0;
up_efds:
	intr_handle->efds = tmp_efds;
fail:
	return -rte_errno;
}

int rte_intr_instance_alloc_flag_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->alloc_flag;
fail:
	return -rte_errno;
}

int rte_intr_event_list_update(struct rte_intr_handle *intr_handle,
				      int size)
{
	struct rte_epoll_event *tmp_elist;
	int *tmp_efds;

	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (size == 0) {
		RTE_LOG(ERR, EAL, "Size can't be zero\n");
		rte_errno = EINVAL;
		goto fail;
	}

	if (IS_RTE_MEMORY(intr_handle))
		tmp_efds = rte_realloc(intr_handle->efds, size *
				       sizeof(uint32_t), 0);
	else
		tmp_efds = realloc(intr_handle->efds, size *
				   sizeof(uint32_t));
	if (tmp_efds == NULL) {
		RTE_LOG(ERR, EAL, "Failed to realloc the efds list");
		rte_errno = ENOMEM;
		goto fail;
	}

	if (IS_RTE_MEMORY(intr_handle))
		tmp_elist = rte_realloc(intr_handle->elist, size *
					sizeof(struct rte_epoll_event),
					0);
	else
		tmp_elist = realloc(intr_handle->elist,	size *
				    sizeof(struct rte_epoll_event));
	if (tmp_elist == NULL) {
		RTE_LOG(ERR, EAL, "Failed to realloc the event list");
		rte_errno = ENOMEM;
		goto up_efds;
	}

	intr_handle->efds = tmp_efds;
	intr_handle->elist = tmp_elist;
	intr_handle->nb_intr = size;

	return 0;
up_efds:
	intr_handle->efds = tmp_efds;
fail:
	return -rte_errno;
}

void rte_intr_instance_free(struct rte_intr_handle *intr_handle)
{
	if (intr_handle != NULL) {
		if (IS_RTE_MEMORY(intr_handle)) {
			rte_free(intr_handle->efds);
			rte_free(intr_handle->elist);
			rte_free(intr_handle);
		} else {
			free(intr_handle->efds);
			free(intr_handle->elist);
			free(intr_handle);
		}
	}
}

int rte_intr_fd_set(struct rte_intr_handle *intr_handle, int fd)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	intr_handle->fd = fd;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_fd_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->fd;
fail:
	return -1;
}

int rte_intr_type_set(struct rte_intr_handle *intr_handle,
		      enum rte_intr_handle_type type)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	intr_handle->type = type;

	return 0;
fail:
	return -rte_errno;
}

enum rte_intr_handle_type rte_intr_type_get(
				const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->type;
fail:
	return RTE_INTR_HANDLE_UNKNOWN;
}

int rte_intr_dev_fd_set(struct rte_intr_handle *intr_handle, int fd)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	intr_handle->dev_fd = fd;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_dev_fd_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->dev_fd;
fail:
	return -1;
}

int rte_intr_max_intr_set(struct rte_intr_handle *intr_handle,
				 int max_intr)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (max_intr > intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Maximum interrupt vector ID (%d) exceeds "
			"the number of available events (%d)\n", max_intr,
			intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->max_intr = max_intr;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_max_intr_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->max_intr;
fail:
	return -rte_errno;
}

int rte_intr_nb_efd_set(struct rte_intr_handle *intr_handle,
				 int nb_efd)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	intr_handle->nb_efd = nb_efd;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_nb_efd_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->nb_efd;
fail:
	return -rte_errno;
}

int rte_intr_nb_intr_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->nb_intr;
fail:
	return -rte_errno;
}

int rte_intr_efd_counter_size_set(struct rte_intr_handle *intr_handle,
				 uint8_t efd_counter_size)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	intr_handle->efd_counter_size = efd_counter_size;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_efd_counter_size_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->efd_counter_size;
fail:
	return -rte_errno;
}

int rte_intr_efds_index_get(const struct rte_intr_handle *intr_handle,
			    int index)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (!intr_handle->efds) {
		RTE_LOG(ERR, EAL, "Event fd list not allocated\n");
		rte_errno = EFAULT;
		goto fail;
	}

	if (index >= intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid size %d, max limit %d\n", index,
			intr_handle->nb_intr);
		rte_errno = EINVAL;
		goto fail;
	}

	return intr_handle->efds[index];
fail:
	return -rte_errno;
}

int rte_intr_efds_index_set(struct rte_intr_handle *intr_handle,
			    int index, int fd)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (!intr_handle->efds) {
		RTE_LOG(ERR, EAL, "Event fd list not allocated\n");
		rte_errno = EFAULT;
		goto fail;
	}

	if (index >= intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid size %d, max limit %d\n", index,
			intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->efds[index] = fd;

	return 0;
fail:
	return -rte_errno;
}

struct rte_epoll_event *rte_intr_elist_index_get(
				struct rte_intr_handle *intr_handle, int index)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (!intr_handle->elist) {
		RTE_LOG(ERR, EAL, "Event list not allocated\n");
		rte_errno = EFAULT;
		goto fail;
	}

	if (index >= intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid index %d, max limit %d\n", index,
			intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	return &intr_handle->elist[index];
fail:
	return NULL;
}

int rte_intr_elist_index_set(struct rte_intr_handle *intr_handle,
			     int index, struct rte_epoll_event elist)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (!intr_handle->elist) {
		RTE_LOG(ERR, EAL, "Event list not allocated\n");
		rte_errno = EFAULT;
		goto fail;
	}

	if (index >= intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid index %d, max limit %d\n", index,
			intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->elist[index] = elist;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_vec_list_alloc(struct rte_intr_handle *intr_handle,
				   const char *name, int size)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	/* Vector list already allocated */
	if (intr_handle->intr_vec != NULL)
		return 0;

	if (size > intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid size %d, max limit %d\n", size,
		       intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->intr_vec = rte_zmalloc(name, size * sizeof(int), 0);
	if (intr_handle->intr_vec == NULL) {
		RTE_LOG(ERR, EAL, "Failed to allocate %d intr_vec", size);
			rte_errno = ENOMEM;
			goto fail;
	}

	intr_handle->vec_list_size = size;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_vec_list_index_get(const struct rte_intr_handle *intr_handle,
				int index)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	RTE_ASSERT(intr_handle->vec_list_size != 0);

	if (index > intr_handle->vec_list_size) {
		RTE_LOG(ERR, EAL, "Index %d greater than vec list size %d\n",
			index, intr_handle->vec_list_size);
		rte_errno = ERANGE;
		goto fail;
	}

	return intr_handle->intr_vec[index];
fail:
	return -rte_errno;
}

int rte_intr_vec_list_index_set(struct rte_intr_handle *intr_handle,
				int index, int vec)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	RTE_ASSERT(intr_handle->vec_list_size != 0);

	if (index > intr_handle->vec_list_size) {
		RTE_LOG(ERR, EAL, "Index %d greater than vec list size %d\n",
			index, intr_handle->vec_list_size);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->intr_vec[index] = vec;

	return 0;
fail:
	return -rte_errno;
}

void rte_intr_vec_list_free(struct rte_intr_handle *intr_handle)
{
	if (intr_handle != NULL) {
		rte_free(intr_handle->intr_vec);
		intr_handle->intr_vec = NULL;
		intr_handle->vec_list_size = 0;
	}
}

void *rte_intr_instance_windows_handle_get(struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->windows_handle;
fail:
	return NULL;
}

int rte_intr_instance_windows_handle_set(struct rte_intr_handle *intr_handle,
					 void *windows_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	intr_handle->windows_handle = windows_handle;

	return 0;
fail:
	return -rte_errno;
}

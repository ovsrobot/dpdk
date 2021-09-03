/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <stdlib.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include <rte_interrupts.h>

struct rte_intr_handle {
	RTE_STD_C11
	union {
		struct {
			/** VFIO/UIO cfg device file descriptor */
			int dev_fd;
			int fd;	/**< interrupt event file descriptor */
		};
		void *handle; /**< device driver handle (Windows) */
	};
	bool alloc_from_hugepage;
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


struct rte_intr_handle *rte_intr_handle_instance_alloc(int size,
						       bool from_hugepage)
{
	struct rte_intr_handle *intr_handle;
	int i;

	if (from_hugepage)
		intr_handle = rte_zmalloc(NULL,
					  size * sizeof(struct rte_intr_handle),
					  0);
	else
		intr_handle = calloc(1, size * sizeof(struct rte_intr_handle));
	if (!intr_handle) {
		RTE_LOG(ERR, EAL, "Fail to allocate intr_handle\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	for (i = 0; i < size; i++) {
		if (from_hugepage)
			intr_handle[i].efds = rte_zmalloc(NULL,
				RTE_MAX_RXTX_INTR_VEC_ID * sizeof(uint32_t), 0);
		else
			intr_handle[i].efds = calloc(1,
				   RTE_MAX_RXTX_INTR_VEC_ID * sizeof(uint32_t));
		if (!intr_handle[i].efds) {
			RTE_LOG(ERR, EAL, "Fail to allocate event fd list\n");
			rte_errno = ENOMEM;
			goto fail;
		}

		if (from_hugepage)
			intr_handle[i].elist = rte_zmalloc(NULL,
					RTE_MAX_RXTX_INTR_VEC_ID *
					sizeof(struct rte_epoll_event), 0);
		else
			intr_handle[i].elist = calloc(1,
					RTE_MAX_RXTX_INTR_VEC_ID *
					sizeof(struct rte_epoll_event));
		if (!intr_handle[i].elist) {
			RTE_LOG(ERR, EAL, "fail to allocate event fd list\n");
			rte_errno = ENOMEM;
			goto fail;
		}
		intr_handle[i].nb_intr = RTE_MAX_RXTX_INTR_VEC_ID;
		intr_handle[i].alloc_from_hugepage = from_hugepage;
	}

	return intr_handle;
fail:
	free(intr_handle->efds);
	free(intr_handle);
	return NULL;
}

struct rte_intr_handle *rte_intr_handle_instance_index_get(
				struct rte_intr_handle *intr_handle, int index)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	return &intr_handle[index];
}

int rte_intr_handle_instance_index_set(struct rte_intr_handle *intr_handle,
				       const struct rte_intr_handle *src,
				       int index)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (src == NULL) {
		RTE_LOG(ERR, EAL, "Source interrupt instance unallocated\n");
		rte_errno = EINVAL;
		goto fail;
	}

	if (index < 0) {
		RTE_LOG(ERR, EAL, "Index cany be negative");
		rte_errno = EINVAL;
		goto fail;
	}

	intr_handle[index].fd = src->fd;
	intr_handle[index].dev_fd = src->dev_fd;

	intr_handle[index].type = src->type;
	intr_handle[index].max_intr = src->max_intr;
	intr_handle[index].nb_efd = src->nb_efd;
	intr_handle[index].efd_counter_size = src->efd_counter_size;

	if (intr_handle[index].nb_intr != src->nb_intr) {
		if (src->alloc_from_hugepage)
			intr_handle[index].efds =
				rte_realloc(intr_handle[index].efds,
					    src->nb_intr *
					    sizeof(uint32_t), 0);
		else
			intr_handle[index].efds =
				realloc(intr_handle[index].efds,
					src->nb_intr * sizeof(uint32_t));
		if (intr_handle[index].efds == NULL) {
			RTE_LOG(ERR, EAL, "Failed to realloc the efds list");
			rte_errno = ENOMEM;
			goto fail;
		}

		if (src->alloc_from_hugepage)
			intr_handle[index].elist =
				rte_realloc(intr_handle[index].elist,
					    src->nb_intr *
					    sizeof(struct rte_epoll_event), 0);
		else
			intr_handle[index].elist =
				realloc(intr_handle[index].elist,
					src->nb_intr *
					sizeof(struct rte_epoll_event));
		if (intr_handle[index].elist == NULL) {
			RTE_LOG(ERR, EAL, "Failed to realloc the event list");
			rte_errno = ENOMEM;
			goto fail;
		}

		intr_handle[index].nb_intr = src->nb_intr;
	}

	memcpy(intr_handle[index].efds, src->efds, src->nb_intr);
	memcpy(intr_handle[index].elist, src->elist, src->nb_intr);

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_event_list_update(struct rte_intr_handle *intr_handle,
				      int size)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (size == 0) {
		RTE_LOG(ERR, EAL, "Size can't be zero\n");
		rte_errno = EINVAL;
		goto fail;
	}

	intr_handle->efds = realloc(intr_handle->efds,
					  size * sizeof(uint32_t));
	if (intr_handle->efds == NULL) {
		RTE_LOG(ERR, EAL, "Failed to realloc the efds list");
		rte_errno = ENOMEM;
		goto fail;
	}

	intr_handle->elist = realloc(intr_handle->elist,
				     size * sizeof(struct rte_epoll_event));
	if (intr_handle->elist == NULL) {
		RTE_LOG(ERR, EAL, "Failed to realloc the event list");
		rte_errno = ENOMEM;
		goto fail;
	}

	intr_handle->nb_intr = size;

	return 0;
fail:
	return rte_errno;
}


void rte_intr_handle_instance_free(struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
	}

	if (intr_handle->alloc_from_hugepage) {
		rte_free(intr_handle->efds);
		rte_free(intr_handle->elist);
		rte_free(intr_handle);
	} else {
		free(intr_handle->efds);
		free(intr_handle->elist);
		free(intr_handle);
	}
}

int rte_intr_handle_fd_set(struct rte_intr_handle *intr_handle, int fd)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->fd = fd;

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_fd_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->fd;
fail:
	return rte_errno;
}

int rte_intr_handle_type_set(struct rte_intr_handle *intr_handle,
			     enum rte_intr_handle_type type)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->type = type;

	return 0;
fail:
	return rte_errno;
}

enum rte_intr_handle_type rte_intr_handle_type_get(
				const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		return RTE_INTR_HANDLE_UNKNOWN;
	}

	return intr_handle->type;
}

int rte_intr_handle_dev_fd_set(struct rte_intr_handle *intr_handle, int fd)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->dev_fd = fd;

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_dev_fd_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->dev_fd;
fail:
	return rte_errno;
}

int rte_intr_handle_max_intr_set(struct rte_intr_handle *intr_handle,
				 int max_intr)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (max_intr > intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Max_intr=%d greater than PLT_MAX_RXTX_INTR_VEC_ID=%d",
			max_intr, intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->max_intr = max_intr;

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_max_intr_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->max_intr;
fail:
	return rte_errno;
}

int rte_intr_handle_nb_efd_set(struct rte_intr_handle *intr_handle,
				 int nb_efd)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->nb_efd = nb_efd;

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_nb_efd_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->nb_efd;
fail:
	return rte_errno;
}

int rte_intr_handle_nb_intr_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->nb_intr;
fail:
	return rte_errno;
}

int rte_intr_handle_efd_counter_size_set(struct rte_intr_handle *intr_handle,
				 uint8_t efd_counter_size)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->efd_counter_size = efd_counter_size;

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_efd_counter_size_get(
				const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->efd_counter_size;
fail:
	return rte_errno;
}

int *rte_intr_handle_efds_base(struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (!intr_handle->efds) {
		RTE_LOG(ERR, EAL, "Event fd list not allocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->efds;
fail:
	return NULL;
}

int rte_intr_handle_efds_index_get(const struct rte_intr_handle *intr_handle,
				   int index)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

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
	return rte_errno;
}

int rte_intr_handle_efds_index_set(struct rte_intr_handle *intr_handle,
				   int index, int fd)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

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
	return rte_errno;
}

struct rte_epoll_event *rte_intr_handle_elist_index_get(
				struct rte_intr_handle *intr_handle, int index)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (!intr_handle->elist) {
		RTE_LOG(ERR, EAL, "Event list not allocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (index >= intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid size %d, max limit %d\n", index,
			intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	return &intr_handle->elist[index];
fail:
	return NULL;
}

int rte_intr_handle_elist_index_set(struct rte_intr_handle *intr_handle,
				   int index, struct rte_epoll_event elist)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (!intr_handle->elist) {
		RTE_LOG(ERR, EAL, "Event list not allocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (index >= intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid size %d, max limit %d\n", index,
			intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->elist[index] = elist;

	return 0;
fail:
	return rte_errno;
}

int *rte_intr_handle_vec_list_base(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		return NULL;
	}

	return intr_handle->intr_vec;
}

int rte_intr_handle_vec_list_alloc(struct rte_intr_handle *intr_handle,
				   const char *name, int size)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	/* Vector list already allocated */
	if (intr_handle->intr_vec)
		return 0;

	if (size > intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Invalid size %d, max limit %d\n", size,
		       intr_handle->nb_intr);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->intr_vec = rte_zmalloc(name, size * sizeof(int), 0);
	if (!intr_handle->intr_vec) {
		RTE_LOG(ERR, EAL, "Failed to allocate %d intr_vec", size);
			rte_errno = ENOMEM;
			goto fail;
	}

	intr_handle->vec_list_size = size;

	return 0;
fail:
	return rte_errno;
}

int rte_intr_handle_vec_list_index_get(
			const struct rte_intr_handle *intr_handle, int index)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (!intr_handle->intr_vec) {
		RTE_LOG(ERR, EAL, "Intr vector list not allocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (index > intr_handle->vec_list_size) {
		RTE_LOG(ERR, EAL, "Index %d greater than vec list size %d\n",
			index, intr_handle->vec_list_size);
		rte_errno = ERANGE;
		goto fail;
	}

	return intr_handle->intr_vec[index];
fail:
	return rte_errno;
}

int rte_intr_handle_vec_list_index_set(struct rte_intr_handle *intr_handle,
				   int index, int vec)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (!intr_handle->intr_vec) {
		RTE_LOG(ERR, EAL, "Intr vector list not allocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (index > intr_handle->vec_list_size) {
		RTE_LOG(ERR, EAL, "Index %d greater than vec list size %d\n",
			index, intr_handle->vec_list_size);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->intr_vec[index] = vec;

	return 0;
fail:
	return rte_errno;
}

void rte_intr_handle_vec_list_free(struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
	}

	rte_free(intr_handle->intr_vec);
	intr_handle->intr_vec = NULL;
}

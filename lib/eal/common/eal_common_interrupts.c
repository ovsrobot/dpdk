/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <stdlib.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include <rte_interrupts.h>


struct rte_intr_handle *rte_intr_instance_alloc(uint32_t flags)
{
	struct rte_intr_handle *intr_handle;
	bool mem_allocator;

	mem_allocator = (flags & RTE_INTR_ALLOC_DPDK_ALLOCATOR) != 0;
	if (mem_allocator)
		intr_handle = rte_zmalloc(NULL, sizeof(struct rte_intr_handle),
					  0);
	else
		intr_handle = calloc(1, sizeof(struct rte_intr_handle));
	if (!intr_handle) {
		RTE_LOG(ERR, EAL, "Fail to allocate intr_handle\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	intr_handle->nb_intr = RTE_MAX_RXTX_INTR_VEC_ID;
	intr_handle->mem_allocator = mem_allocator;

	return intr_handle;
}

int rte_intr_instance_copy(struct rte_intr_handle *intr_handle,
			   const struct rte_intr_handle *src)
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

	intr_handle->fd = src->fd;
	intr_handle->vfio_dev_fd = src->vfio_dev_fd;
	intr_handle->type = src->type;
	intr_handle->max_intr = src->max_intr;
	intr_handle->nb_efd = src->nb_efd;
	intr_handle->efd_counter_size = src->efd_counter_size;

	memcpy(intr_handle->efds, src->efds, src->nb_intr);
	memcpy(intr_handle->elist, src->elist, src->nb_intr);

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_instance_mem_allocator_get(
				const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		return -ENOTSUP;
	}

	return intr_handle->mem_allocator;
}

void rte_intr_instance_free(struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
	}

	if (intr_handle->mem_allocator)
		rte_free(intr_handle);
	else
		free(intr_handle);
}

int rte_intr_fd_set(struct rte_intr_handle *intr_handle, int fd)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->fd = fd;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_fd_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->fd;
fail:
	return -1;
}

int rte_intr_type_set(struct rte_intr_handle *intr_handle,
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
	return -rte_errno;
}

enum rte_intr_handle_type rte_intr_type_get(
				const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		return RTE_INTR_HANDLE_UNKNOWN;
	}

	return intr_handle->type;
}

int rte_intr_dev_fd_set(struct rte_intr_handle *intr_handle, int fd)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	intr_handle->vfio_dev_fd = fd;

	return 0;
fail:
	return -rte_errno;
}

int rte_intr_dev_fd_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->vfio_dev_fd;
fail:
	return -1;
}

int rte_intr_max_intr_set(struct rte_intr_handle *intr_handle,
				 int max_intr)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	if (max_intr > intr_handle->nb_intr) {
		RTE_LOG(ERR, EAL, "Max_intr=%d greater than RTE_MAX_RXTX_INTR_VEC_ID=%d",
			max_intr, intr_handle->nb_intr);
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
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->max_intr;
fail:
	return -rte_errno;
}

int rte_intr_nb_efd_set(struct rte_intr_handle *intr_handle,
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
	return -rte_errno;
}

int rte_intr_nb_efd_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->nb_efd;
fail:
	return -rte_errno;
}

int rte_intr_nb_intr_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->nb_intr;
fail:
	return -rte_errno;
}

int rte_intr_efd_counter_size_set(struct rte_intr_handle *intr_handle,
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
	return -rte_errno;
}

int rte_intr_efd_counter_size_get(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
		goto fail;
	}

	return intr_handle->efd_counter_size;
fail:
	return -rte_errno;
}

int rte_intr_efds_index_get(const struct rte_intr_handle *intr_handle,
				   int index)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
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
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
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
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
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

int rte_intr_elist_index_set(struct rte_intr_handle *intr_handle,
				   int index, struct rte_epoll_event elist)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
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
	return -rte_errno;
}

int rte_intr_vec_list_alloc(struct rte_intr_handle *intr_handle,
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
	return -rte_errno;
}

int rte_intr_vec_list_index_get(const struct rte_intr_handle *intr_handle,
				int index)
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
	return -rte_errno;
}

int rte_intr_vec_list_index_set(struct rte_intr_handle *intr_handle,
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
	return -rte_errno;
}

void rte_intr_vec_list_free(struct rte_intr_handle *intr_handle)
{
	if (intr_handle == NULL) {
		RTE_LOG(ERR, EAL, "Interrupt instance unallocated\n");
		rte_errno = ENOTSUP;
	}

	rte_free(intr_handle->intr_vec);
	intr_handle->intr_vec = NULL;
}

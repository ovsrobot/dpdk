/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Dmitry Kozlyuk
 */

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>

#include "eal_private.h"
#include "eal_filesystem.h"
#include "eal_hugepages.h"
#include "eal_internal_cfg.h"
#include "eal_windows.h"

static int
hugepage_claim_privilege(void)
{
	static const wchar_t privilege[] = L"SeLockMemoryPrivilege";

	HANDLE token;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	int ret = -1;

	if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES, &token)) {
		RTE_LOG_WIN32_ERR("OpenProcessToken()");
		return -1;
	}

	if (!LookupPrivilegeValueW(NULL, privilege, &luid)) {
		RTE_LOG_WIN32_ERR("LookupPrivilegeValue(\"%S\")", privilege);
		goto exit;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
			token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
		RTE_LOG_WIN32_ERR("AdjustTokenPrivileges()");
		goto exit;
	}

	/* AdjustTokenPrivileges() may succeed with ERROR_NOT_ALL_ASSIGNED. */
	if (GetLastError() != ERROR_SUCCESS)
		goto exit;

	ret = 0;

exit:
	CloseHandle(token);

	return ret;
}

static int
hugepage_info_init(void)
{
	struct hugepage_info *hpi;
	unsigned int socket_id;
	int ret = 0;
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();

	hpi = &runtime_state->hugepage_info[0];

	hpi->hugepage_sz = GetLargePageMinimum();
	if (hpi->hugepage_sz == 0)
		return -ENOTSUP;

	/* Assume all memory on each NUMA node available for hugepages,
	 * because Windows neither advertises additional limits,
	 * nor provides an API to query them.
	 */
	for (socket_id = 0; socket_id < rte_socket_count(); socket_id++) {
		ULONGLONG bytes;
		unsigned int numa_node;

		numa_node = eal_socket_numa_node(socket_id);
		if (!GetNumaAvailableMemoryNodeEx(numa_node, &bytes)) {
			RTE_LOG_WIN32_ERR("GetNumaAvailableMemoryNodeEx(%u)",
				numa_node);
			continue;
		}

		hpi->num_pages[socket_id] = bytes / hpi->hugepage_sz;
		EAL_LOG(DEBUG,
			"Found %u hugepages of %zu bytes on socket %u",
			hpi->num_pages[socket_id], hpi->hugepage_sz, socket_id);
	}

	/* No hugepage filesystem on Windows. */
	hpi->lock_descriptor = -1;
	memset(hpi->hugedir, 0, sizeof(hpi->hugedir));
	runtime_state->num_hugepage_sizes = 1;

	return ret;
}

int
eal_get_platform_hp_info(struct eal_platform_info *platform_info)
{
	size_t hp_sz;
	unsigned int socket_id;

	hp_sz = GetLargePageMinimum();
	if (hp_sz == 0)
		return -ENOTSUP;

	for (socket_id = 0; socket_id < platform_info->numa_node_count; socket_id++) {
		ULONGLONG bytes;
		unsigned int numa_node;

		numa_node = eal_socket_numa_node(socket_id);
		if (GetNumaAvailableMemoryNodeEx(numa_node, &bytes)) {
			platform_info->hugepage_sizes[0].max_pages[socket_id] = bytes / hp_sz;
			platform_info->hugepage_sizes[0].total_pages += bytes / hp_sz;
		}
	}

	platform_info->num_hugepage_sizes = 1;
	platform_info->hugepage_sizes[0].size = hp_sz;
	platform_info->hugepage_sizes[0].dir[0] = '\0'; /* no hugetlbfs on Windows */

	return 0;
}

int
eal_hugepage_info_init(void)
{
	if (hugepage_claim_privilege() < 0) {
		EAL_LOG(ERR,
			"Cannot claim hugepage privilege, check large-page support privilege");
		return -1;
	}

	if (hugepage_info_init() < 0) {
		EAL_LOG(ERR, "Cannot discover available hugepages");
		return -1;
	}

	return 0;
}

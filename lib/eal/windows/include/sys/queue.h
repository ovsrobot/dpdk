/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Windows has no system <sys/queue.h>. The bundled copy has moved to
 * <rte_queue.h>; this stub keeps the existing includes working until they
 * are converted, and is removed in the following commit.
 */

#include <rte_queue.h>

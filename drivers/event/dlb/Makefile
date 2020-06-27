# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2016-2020 Intel Corporation.

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_pmd_dlb_eventdev.a

# build flags
CFLAGS += -O3 -pthread
CFLAGS += $(WERROR_FLAGS)
# rte_mp_ APIs are still marked experimental
LDLIBS += -lrte_eal -lrte_eventdev -lrte_mbuf -lrte_kvargs -lrte_ring
LDLIBS += -lrte_mempool -lpthread -lrte_pci -lrte_bus_pci

# library version
LIBABIVER := 1

# versioning export map
EXPORT_MAP := rte_pmd_dlb_event_version.map

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DLB_EVENTDEV) += pf/dlb_pf.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DLB_EVENTDEV) += pf/dlb_main.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DLB_EVENTDEV) += pf/base/dlb_resource.c

# export include files

include $(RTE_SDK)/mk/rte.lib.mk

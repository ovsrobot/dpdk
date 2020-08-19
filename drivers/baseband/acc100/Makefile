# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_pmd_bbdev_acc100.a

# build flags
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring -lrte_cfgfile
LDLIBS += -lrte_bbdev
LDLIBS += -lrte_pci -lrte_bus_pci

# versioning export map
EXPORT_MAP := rte_pmd_bbdev_acc100_version.map

# library version
LIBABIVER := 1

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_ACC100) += rte_acc100_pmd.c

include $(RTE_SDK)/mk/rte.lib.mk

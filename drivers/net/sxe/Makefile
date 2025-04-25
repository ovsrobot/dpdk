# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2016 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_sxe.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -DSXE_DPDK
CFLAGS += -DSXE_HOST_DRIVER
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_pmd_sxe_version.map


ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
#
# CFLAGS for icc
#
CFLAGS_BASE_DRIVER  = -diag-disable 174 -diag-disable 593 -diag-disable 869
CFLAGS_BASE_DRIVER += -diag-disable 981 -diag-disable 2259

else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
#
# CFLAGS for clang
#
CFLAGS_BASE_DRIVER = -Wno-unused-parameter -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing -Wno-format-extra-args

else
#
# CFLAGS for gcc
#
CFLAGS_BASE_DRIVER = -Wno-unused-parameter -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing -Wno-format-extra-args
CFLAGS_BASE_DRIVER += -Wmissing-prototypes

endif
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_hash
LDLIBS += -lrte_bus_pci
LDLIBS += -lpthread

#
# Add extra flags for base driver files (also known as shared code)
# to disable warnings in them
#

$(shell cp $(SRCDIR)/pf/* $(SRCDIR))
$(shell cp $(SRCDIR)/base/* $(SRCDIR))
$(shell cp $(SRCDIR)/include/*.h $(SRCDIR))
$(shell cp $(SRCDIR)/include/sxe/*.h $(SRCDIR))
$(warning "file copy done")

SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_common.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_hw.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_offload_common.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_queue_common.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_rx_common.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_tx_common.c

SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_dcb.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_filter.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_flow_ctrl.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_irq.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_main.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_offload.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_phy.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_pmd_hdc.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_ptp.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_queue.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_stats.c
SRCS-$(CONFIG_RTE_LIBRTE_SXE_PMD) += sxe_tx.c

# install this header file
SYMLINK-$(CONFIG_RTE_LIBRTE_SXE_PMD)-include := rte_pmd_sxe.h
SYMLINK-$(CONFIG_RTE_LIBRTE_SXE_PMD)-include += sxe_dcb.h

include $(RTE_SDK)/mk/rte.lib.mk

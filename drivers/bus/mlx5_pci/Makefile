# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_bus_mlx5_pci.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(RTE_SDK)/drivers/common/mlx5
CFLAGS += -I$(BUILDDIR)/drivers/common/mlx5
CFLAGS += -I$(RTE_SDK)/drivers/bus/pci
LDLIBS += -lrte_eal
LDLIBS += -lrte_common_mlx5
LDLIBS += -lrte_pci -lrte_bus_pci

# versioning export map
EXPORT_MAP := rte_bus_mlx5_pci_version.map

SRCS-y += mlx5_pci_bus.c

# DEBUG which is usually provided on the command-line may enable
# CONFIG_RTE_LIBRTE_MLX5_DEBUG.
ifeq ($(DEBUG),1)
CONFIG_RTE_LIBRTE_MLX5_DEBUG := y
endif

# User-defined CFLAGS.
ifeq ($(CONFIG_RTE_LIBRTE_MLX5_DEBUG),y)
CFLAGS += -pedantic
ifneq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS += -DPEDANTIC
endif
AUTO_CONFIG_CFLAGS += -Wno-pedantic
else
CFLAGS += -UPEDANTIC
endif

#
# Export include files
#
SYMLINK-y-include += rte_bus_mlx5_pci.h

include $(RTE_SDK)/mk/rte.lib.mk

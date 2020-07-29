# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Mellanox Technologies, Ltd

include $(RTE_SDK)/mk/rte.vars.mk

APP = testregex

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API

#
# all source are stored in SRCS-y
#
SRCS-y := main.c

include $(RTE_SDK)/mk/rte.app.mk

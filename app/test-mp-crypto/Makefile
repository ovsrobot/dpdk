# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk


APP = dpdk-test-mp-crypto

CFLAGS += $(WERROR_FLAGS)
CFLAGS += -O3

# all source are stored in SRCS-y
SRCS-y := main.c mp_crypto.c mp_crypto_parser.c mp_crypto_ipc.c mp_crypto_vectors.c

include $(RTE_SDK)/mk/rte.app.mk

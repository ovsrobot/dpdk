# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_vhost.a

EXPORT_MAP := rte_vhost_version.map

CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR) -O3
CFLAGS += -I vhost_user
CFLAGS += -fno-strict-aliasing
LDLIBS += -lpthread

ifeq ($(RTE_TOOLCHAIN), gcc)
ifeq ($(shell test $(GCC_VERSION) -ge 83 && echo 1), 1)
CFLAGS += -DVHOST_GCC_UNROLL_PRAGMA
endif
endif

ifeq ($(RTE_TOOLCHAIN), clang)
ifeq ($(shell test $(CLANG_MAJOR_VERSION)$(CLANG_MINOR_VERSION) -ge 37 && echo 1), 1)
CFLAGS += -DVHOST_CLANG_UNROLL_PRAGMA
endif
endif

ifeq ($(RTE_TOOLCHAIN), icc)
ifeq ($(shell test $(ICC_MAJOR_VERSION) -ge 16 && echo 1), 1)
CFLAGS += -DVHOST_ICC_UNROLL_PRAGMA
endif
endif

ifneq ($(FORCE_DISABLE_AVX512), y)
        CC_AVX512_SUPPORT=\
        $(shell $(CC) -march=native -dM -E - </dev/null 2>&1 | \
        sed '/./{H;$$!d} ; x ; /AVX512F/!d; /AVX512BW/!d; /AVX512VL/!d' | \
        grep -q AVX512 && echo 1)
endif

ifeq ($(CONFIG_RTE_LIBRTE_VHOST_NUMA),y)
LDLIBS += -lnuma
endif
LDLIBS += -lrte_eal -lrte_mempool -lrte_mbuf -lrte_ethdev -lrte_net

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_VHOST) := fd_man.c iotlb.c socket.c vhost.c \
					vhost_user.c virtio_net.c vdpa.c

ifeq ($(CC_AVX512_SUPPORT), 1)
CFLAGS += -DCC_AVX512_SUPPORT
SRCS-$(CONFIG_RTE_LIBRTE_VHOST) += vhost_vec_avx.c
CFLAGS_vhost_vec_avx.o += -mavx512f -mavx512bw -mavx512vl
endif

# install includes
SYMLINK-$(CONFIG_RTE_LIBRTE_VHOST)-include += rte_vhost.h rte_vdpa.h \
						rte_vdpa_dev.h rte_vhost_async.h

# only compile vhost crypto when cryptodev is enabled
ifeq ($(CONFIG_RTE_LIBRTE_CRYPTODEV),y)
LDLIBS += -lrte_cryptodev -lrte_hash
SRCS-$(CONFIG_RTE_LIBRTE_VHOST) += vhost_crypto.c
SYMLINK-$(CONFIG_RTE_LIBRTE_VHOST)-include += rte_vhost_crypto.h
endif

include $(RTE_SDK)/mk/rte.lib.mk

# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Red Hat, Inc.

ifeq ($(V),)
Q ?= @
else
Q =
endif

O ?= build

PKGCONF ?= pkg-config

ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

ifeq ($(I),)

.PHONY: headers_list
.ONESHELL:
headers_list:
	$(Q)for dir in $$($(PKGCONF) --cflags-only-I libdpdk); do
		dir=$${dir##-I}
		[ -e $$dir/rte_build_config.h ] || continue
		$(MAKE) I="$$dir" O="$(O)"
		break
	done
else

HEADERS := $(shell find $(I) -name "*.h" | grep -vE $(I)'/(generic|internal)/')
SRCS := $(patsubst $(I)/%.h, $(O)/%.c, $(HEADERS))
.PRECIOUS: $(SRCS)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS = $(shell $(PKGCONF) --cflags libdpdk) -Wall -Wextra -Werror
LDFLAGS = $(shell $(PKGCONF) --libs libdpdk)

OBJS := $(patsubst $(I)/%.h, $(O)/%.o, $(HEADERS))
OBJS_EXP := $(patsubst $(I)/%.h, $(O)/%+exp.o, $(HEADERS))
OBJS_ALL := $(patsubst $(I)/%.h, $(O)/%+all.o, $(HEADERS))

all: $(OBJS) $(OBJS_EXP) $(OBJS_ALL)

$(O):
	$(Q)mkdir -p $@

$(O)/%.c: $(I)/%.h $(O) gen_c_file_for_header.py Makefile
	$(Q)python3 gen_c_file_for_header.py $< $@

$(O)/%.o: $(O)/%.c Makefile $(PC_FILE)
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(O)/%+exp.o: $(O)/%.c Makefile $(PC_FILE)
	$(Q)$(CC) $(CFLAGS) -DALLOW_EXPERIMENTAL_API -o $@ -c $<

$(O)/%+all.o: $(O)/%.c Makefile $(PC_FILE)
	$(Q)$(CC) $(CFLAGS) -DALLOW_EXPERIMENTAL_API -DALLOW_INTERNAL_API -o $@ -c $<

CXXFLAGS = $(shell $(PKGCONF) --cflags libdpdk) -Wall -Wextra -Werror

OBJS_CPP := $(patsubst $(I)/%.h, $(O)/%.cpp.o, $(HEADERS))
OBJS_CPP_EXP := $(patsubst $(I)/%.h, $(O)/%.cpp+exp.o, $(HEADERS))
OBJS_CPP_ALL := $(patsubst $(I)/%.h, $(O)/%.cpp+all.o, $(HEADERS))

all: $(OBJS_CPP) $(OBJS_CPP_EXP) $(OBJS_CPP_ALL)

$(O)/%.cpp.o: $(O)/%.c Makefile $(PC_FILE)
	$(Q)$(CXX) $(CXXFLAGS) -o $@ -c $<

$(O)/%.cpp+exp.o: $(O)/%.c Makefile $(PC_FILE)
	$(Q)$(CXX) $(CXXFLAGS) -DALLOW_EXPERIMENTAL_API -o $@ -c $<

$(O)/%.cpp+all.o: $(O)/%.c Makefile $(PC_FILE)
	$(Q)$(CXX) $(CXXFLAGS) -DALLOW_EXPERIMENTAL_API -DALLOW_INTERNAL_API -o $@ -c $<

endif

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Siemens AG

APP = l2reflect
SOURCES := main.c stats.c
OBJECTS = $(SOURCES:%.c=%.o)

ifneq ($(RTE_SDK),)
	RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))
	include $(RTE_SDK)/mk/rte.vars.mk
	SRCS-y := $(SOURCES)
	CFLAGS += -O3 -Wall -Wpedantic -Werror
else
	CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)
	LDFLAGS += -Wl,-static $(shell pkg-config --static --libs libdpdk)
endif
CFLAGS += -DRTE_HAS_CJSON -Wstrict-prototypes -Wsign-compare -Wunused-parameter -Wunused-parameter
LDFLAGS += -lcjson

ifeq ($(RTE_SDK),)
%.o: %.c Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

$(APP): $(OBJECTS) Makefile
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(APP) $(OBJECTS)
else
	include $(RTE_SDK)/mk/rte.extapp.mk
endif

# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 NXP

subdirs := ntb

.PHONY: all static shared clean $(subdirs)
all static shared clean: $(subdirs)

$(subdirs):
	$(MAKE) -C $@ $(MAKECMDGOALS)

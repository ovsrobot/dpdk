# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.

doc_targets = []
doc_target_names = []

subdir('doc')

if doc_targets.length() == 0
    message = 'No docs targets found'
else
    message = 'Built docs:'
endif
run_target('dts-doc', command: [echo, message, doc_target_names],
    depends: doc_targets)

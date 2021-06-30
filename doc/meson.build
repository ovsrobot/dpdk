# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

doc_targets = []
doc_target_names = []
subdir('api')
subdir('guides')

if doc_targets.length() == 0
    message = 'No docs targets found'
else
    message = 'Building docs:'
endif
echo = [py3, '-c', 'import sys; print(*sys.argv[1:])']
run_target('doc', command: [echo, message, doc_target_names],
    depends: doc_targets)

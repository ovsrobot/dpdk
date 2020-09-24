# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 Datapath Limited

project('pthreads4w', 'C',
	# Fallback to "more" for Windows compatibility.
	version: run_command(find_program('cat', 'more'),
		files('VERSION')).stdout().strip(),
	license: 'APACHE2.0',
	default_options: ['buildtype=release', 'default_library=static'],
	meson_version: '>= 0.55.0'
)

sources = files(
	'pthread.c'
)

objs = []
cflags = ['-DHAVE_CONFIG_H']

# The static library is built differently to ensure the process attach/detach and thread attach/detach operate correctly.
cflags_static = cflags
cflags_static += '-D__PTW32_STATIC_LIB'
pthreads4w_static_lib = static_library('pthreads4w',
      sources,
      objects: objs,
      c_args: cflags_static,
      install: true)

pthreads4w_shared_lib = shared_library('pthreads4w',
	sources,
	objects: objs,
	c_args: cflags,
	implib: true,
	install: true)

pthreads4w_static_dep = declare_dependency(
	include_directories: '',
	link_with : pthreads4w_static_lib)

pthreads4w_shared_dep = declare_dependency(
	include_directories: '',
	link_with : pthreads4w_shared_lib)

install_headers(
	 'pthread.h',
	 '_ptw32.h',
	 'sched.h',
	 'semaphore.h')


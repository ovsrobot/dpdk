# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2019 Intel Corporation

pkgconf = find_program('pkg-config', 'pkgconf', required: false)
pmdinfo = find_program('gen-pmdinfo-cfile.sh')
list_dir_globs = find_program('list-dir-globs.py')
check_symbols = find_program('check-symbols.sh')
ldflags_ibverbs_static = find_program('options-ibverbs-static.sh')
binutils_avx512_check = find_program('binutils-avx512-check.sh')

# set up map-to-win script using python, either built-in or external
python3 = import('python').find_installation(required: false)
if python3.found()
	py3 = [python3]
else
	py3 = ['meson', 'runpython']
endif
map_to_win_cmd = py3 + files('map_to_win.py')
sphinx_wrapper = py3 + files('call-sphinx-build.py')

abi_check_version = get_option('abi_checks')
check_abi = (abi_check_version != '')

abi_dir = ''
# If abi checks enabled setup abi dump directory
if check_abi
	message('ABI checks are being setup. This could take several minutes')
	setup_run = run_command('abi-setup.py', '-t', abi_check_version, '-d', meson.source_root())
	# Check if error returned from script
	if setup_run.returncode() != 0
		setup_err = setup_run.stderr().strip()
		error('ABI checks setup script returned an error: ' + setup_err)
	endif
	abi_dir = setup_run.stdout().strip()
endif
abidiff = find_program('abidiff', required: check_abi)
abignore = files('../devtools/libabigail.abignore')

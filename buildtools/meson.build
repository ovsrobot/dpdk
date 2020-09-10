# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2019 Intel Corporation

pkgconf = find_program('pkg-config', 'pkgconf', required: false)
pmdinfo = find_program('gen-pmdinfo-cfile.sh')
list_dir_globs = find_program('list-dir-globs.py')
check_symbols = find_program('check-symbols.sh')
ldflags_ibverbs_static = find_program('options-ibverbs-static.sh')
binutils_avx512_check = find_program('binutils-avx512-check.sh')

abi_checks = get_option('abi_checks')
abi_dir = ''
# If abi checks enabled setup abi dump directory
if abi_checks!=''
	message('ABI Checks are being setup, If DPDK_ABI_TAR_URI has not been set these checks may be need to be generated this could take several minutes')
	setup_check = run_command('abi-setup.py','-t',abi_checks,'-d',meson.source_root()).stdout().strip()
	# Check if error returned from script
	if setup_check.startswith('ERROR')
		error('ABI checks setup failed: '+setup_check)
	# No error then set abi directory
	else
		abi_dir=setup_check
	endif
endif
abidiff = find_program('abidiff', required: abi_checks!='')
if abidiff.found()==false and abi_checks!=''
	error('ABI checks require abidiff to to be completed')
endif
abignore = files(meson.source_root()+'/devtools/libabigail.abignore')

# set up map-to-win script using python, either built-in or external
python3 = import('python').find_installation(required: false)
if python3.found()
	py3 = [python3]
else
	py3 = ['meson', 'runpython']
endif
map_to_win_cmd = py3 + files('map_to_win.py')
sphinx_wrapper = py3 + files('call-sphinx-build.py')

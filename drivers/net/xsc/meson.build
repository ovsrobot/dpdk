# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2024 Yunsilicon Technology Co., Ltd.

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

sources = files(
        'xsc_ethdev.c',
        'xsc_dev.c',
        'xsc_utils.c',
        'xsc_ctrl.c',
        'xsc_rxtx.c',
)

libnames = ['ibverbs']
foreach libname:libnames
    lib = dependency('lib' + libname, required: false, method : 'pkg-config')
    if lib.found()
        ext_deps += lib
    else
        build = false
        reason = 'missing dependency, "' + libname + '"'
        subdir_done()
    endif
endforeach

lib = dependency('libxscale', required: false, method : 'pkg-config')
if lib.found()
    ext_deps += lib
    cflags += '-DHAVE_XSC_DV_PROVIDER=1'
else
    cflags += '-DHAVE_XSC_DV_PROVIDER=0'
endif

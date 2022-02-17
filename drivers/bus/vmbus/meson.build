# SPDX-License-Identifier: BSD-3-Clause

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif


headers = files('rte_bus_vmbus.h','rte_vmbus_reg.h')

sources = files(
        'vmbus_bufring.c',
        'vmbus_channel.c',
        'vmbus_common.c',
        'vmbus_common_uio.c',
)

if is_linux
    sources += files('linux/vmbus_bus.c',
            'linux/vmbus_uio.c')
    includes += include_directories('linux')
elif is_freebsd
    sources += files('freebsd/vmbus_bus.c',
	  'freebsd/vmbus_uio.c')
    includes += include_directories('freebsd')
else
    build = false
    reason = 'only supported on Linux & FreeBSD'
endif

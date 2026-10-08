# SPDX-License-Identifier: BSD-3-Clause

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

driver_sdk_headers = files(
        'bus_vmbus_driver.h',
        'vmbus_api.h',
        'vmbus_reg.h',
)

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
else
    build = false
    reason = 'only supported on Linux'
endif

require_iova_in_mbuf = false

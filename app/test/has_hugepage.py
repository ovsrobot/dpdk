#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Microsoft Corporation

import os
import platform

osName = platform.system()
if osName == "Linux":
        file_o=open("/proc/sys/vm/nr_hugepages")
        content=file_o.read()
        print(content)
        file_o.close()
elif osName == "FreeBSD":
        # Assume FreeBSD always has hugepages enabled
        print("1")
elif osName == "Windows":
        # On Windows, check if the Administrator has "Lock pages in memory" security setting
        # to determine if large page is enabled or not

        # Export the USER_RIGHTS security settings
        # Use os.popen instead of os.system to suppress the output of secedit to stdout
        userRightsfile = "userrights.inf"
        os.popen('secedit /export /areas USER_RIGHTS /cfg "' + userRightsfile + '"')

        # Parse the exported user rights setting to determine if Administrator
        # SeLockMemoryPrivilege being set or not
        largepageEnabledStr = 'SeLockMemoryPrivilege = Administrator'
        enabled = 0
        # On different OS versions tested, the exported inf file has utf-16 encoding
        with open(userRightsfile, encoding = 'utf-16') as f:
            urcontent = f.readlines()
            for line in urcontent:
                if largepageEnabledStr in line:
                    enabled = 1
                    break

        f.close()
        print(enabled)
else:
        print("0")

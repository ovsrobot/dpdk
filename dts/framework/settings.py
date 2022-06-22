# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
#

import os
import re

"""
Default session timeout.
"""
TIMEOUT = 15

"""
DTS global environment variables
"""
DTS_ENV_PAT = r"DTS_*"
DTS_CFG_FOLDER = "DTS_CFG_FOLDER"


def load_global_setting(key):
    """
    Load DTS global setting
    """
    if re.match(DTS_ENV_PAT, key):
        env_key = key
    else:
        env_key = "DTS_" + key

    if env_key in list(os.environ.keys()):
        return os.environ[env_key]
    else:
        return ""


"""
The root path of framework configs.
"""
dts_cfg_folder = load_global_setting(DTS_CFG_FOLDER)
if dts_cfg_folder != "":
    CONFIG_ROOT_PATH = dts_cfg_folder
else:
    CONFIG_ROOT_PATH = "./conf"

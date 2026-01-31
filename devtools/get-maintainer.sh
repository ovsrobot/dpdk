#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
#
# Wrapper script for get_maintainer.py for backward compatibility

SCRIPT_DIR=$(dirname $(readlink -f $0))

exec python3 "$SCRIPT_DIR/get-maintainer.py" "$@"

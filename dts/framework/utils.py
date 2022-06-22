# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#


def RED(text):
    return "\x1B[" + "31;1m" + str(text) + "\x1B[" + "0m"


def GREEN(text):
    return "\x1B[" + "32;1m" + str(text) + "\x1B[" + "0m"

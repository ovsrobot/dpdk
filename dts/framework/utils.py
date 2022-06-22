# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

import sys
import threading
from functools import wraps


def create_parallel_locks(num_suts):
    """
    Create thread lock dictionary based on SUTs number
    """
    global locks_info
    locks_info = []
    for _ in range(num_suts):
        lock_info = dict()
        lock_info["update_lock"] = threading.RLock()
        locks_info.append(lock_info)


def parallel_lock(num=1):
    """
    Wrapper function for protect parallel threads, allow multiple threads
    share one lock. Locks are created based on function name. Thread locks are
    separated between SUTs according to argument 'sut_id'.
    Parameter:
        num: Number of parallel threads for the lock
    """
    global locks_info

    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "sut_id" in kwargs:
                sut_id = kwargs["sut_id"]
            else:
                sut_id = 0

            # in case function arguments is not correct
            if sut_id >= len(locks_info):
                sut_id = 0

            lock_info = locks_info[sut_id]
            uplock = lock_info["update_lock"]

            name = func.__name__
            uplock.acquire()

            if name not in lock_info:
                lock_info[name] = dict()
                lock_info[name]["lock"] = threading.RLock()
                lock_info[name]["current_thread"] = 1
            else:
                lock_info[name]["current_thread"] += 1

            lock = lock_info[name]["lock"]

            # make sure when owned global lock, should also own update lock
            if lock_info[name]["current_thread"] >= num:
                if lock._is_owned():
                    print(
                        RED(
                            "SUT%d %s waiting for func lock %s"
                            % (sut_id, threading.current_thread().name, func.__name__)
                        )
                    )
                lock.acquire()
            else:
                uplock.release()

            try:
                ret = func(*args, **kwargs)
            except Exception as e:
                if not uplock._is_owned():
                    uplock.acquire()

                if lock._is_owned():
                    lock.release()
                    lock_info[name]["current_thread"] = 0
                uplock.release()
                raise e

            if not uplock._is_owned():
                uplock.acquire()

            if lock._is_owned():
                lock.release()
                lock_info[name]["current_thread"] = 0

            uplock.release()

            return ret

        return wrapper

    return decorate


def RED(text):
    return "\x1B[" + "31;1m" + str(text) + "\x1B[" + "0m"


def GREEN(text):
    return "\x1B[" + "32;1m" + str(text) + "\x1B[" + "0m"


def check_dts_python_version():
    if (
        sys.version_info.major < 3
        or (sys.version_info.major == 3 and sys.version_info.minor < 6)
        or (
            sys.version_info.major == 3
            and sys.version_info.minor == 6
            and sys.version_info.micro < 9
        )
    ):
        print(
            RED(
                (
                    "WARNING: Dts running node python version is lower than python 3.6, "
                    "it is deprecated for use in DTS, "
                    "and will not work in future releases."
                )
            ),
            file=sys.stderr,
        )
        print(RED("Please use Python >= 3.6.9 instead"), file=sys.stderr)

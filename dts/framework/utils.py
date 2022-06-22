# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

import threading
from functools import wraps


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

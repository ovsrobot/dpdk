# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import threading
from functools import wraps
from typing import Any, Callable, TypeVar

locks_info: list[dict[str, Any]] = list()

T = TypeVar("T")


def parallel_lock(num: int = 1) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Wrapper function for protect parallel threads, allow multiple threads
    share one lock. Locks are created based on function name. Thread locks are
    separated between SUTs according to argument 'sut_id'.
    Parameter:
        num: Number of parallel threads for the lock
    """
    global locks_info

    def decorate(func: Callable[..., T]) -> Callable[..., T]:
        # mypy does not know how to handle the types of this function, so Any is required
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
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
                            f"SUT{sut_id:d} {threading.current_thread().name} waiting for func lock {func.__name__}"
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


def RED(text: str) -> str:
    return f"\u001B[31;1m{str(text)}\u001B[0m"


def GREEN(text: str) -> str:
    return f"\u001B[32;1m{str(text)}\u001B[0m"

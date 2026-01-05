# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""Cryptodev types module.

Exposes types used in the Cryptodev API.
"""

from dataclasses import dataclass, field

from framework.parser import TextParser


@dataclass
class CryptodevResults(TextParser):
    """A happy class docstring."""

    def __iter__(self):
        """Iteration method to parse result objects.

        Yields:
            tuple[str, int | float]: a field name and its value.
        """
        for field_name in self.__dataclass_fields__:
            yield field_name, getattr(self, field_name)


@dataclass
class ThroughputResults(CryptodevResults):
    """A happy class docstring."""

    lcore_id: int = field(metadata=TextParser.find_int(r"\s*(\d+)"))
    buffer_size: int = field(
        metadata=TextParser.find_int(r"\s+(?:\d+\s+)(\d+)"),
    )
    burst_size: int = field(
        metadata=TextParser.find_int(r"\s+(?:\d+\s+){2}(\d+)"),
    )
    enqueued: int = field(metadata=TextParser.find_int(r"\s+(?:\d+\s+){3}(\d+)"))
    dequeued: int = field(metadata=TextParser.find_int(r"\s+(?:\d+\s+){4}(\d+)"))
    failed_enqueue: int = field(metadata=TextParser.find_int(r"\s+(?:\d+\s+){5}(\d+)"))
    failed_dequeue: int = field(metadata=TextParser.find_int(r"\s+(?:\d+\s+){6}(\d+)"))
    mops: float = field(metadata=TextParser.find_float(r"\s+(?:\d+\s+){7}([\d.]+)"))
    gbps: float = field(metadata=TextParser.find_float(r"\s+(?:\d+\s+){7}(?:[\d.]+\s+)([\d.]+)"))
    cycles_per_buffer: float = field(
        metadata=TextParser.find_float(r"\s+(?:\d+\s+){7}(?:[\d.]+\s+){2}([\d.]+)")
    )


@dataclass
class LatencyResults(CryptodevResults):
    """A parser for latency test output."""

    buffer_size: int = field(
        metadata=TextParser.find_int(r"Buf(?:.*\n\s+\d+\s+)?(?:fer size:\s+)?(\d+)"),
    )
    burst_size: int = field(
        metadata=TextParser.find_int(rf"Burst(?:.*\n\s+\d+\s+){2}?(?: size:\s+)?(\d+)"),
    )

    # total_ops: int = field(metadata=TextParser.find_int(r"total operations:\s+(\d+)"))
    # num_of_bursts: int = field(metadata=TextParser.find_int(r"Number of bursts:\s+(\d+)"))
    min_enqueued: int = field(metadata=TextParser.find_int(r"enqueued\s+(?:\d+\s+){2}(\d+)"))
    max_enqueued: int = field(metadata=TextParser.find_int(r"enqueued\s+(?:\d+\s+){3}(\d+)"))
    avg_enqueued: int = field(metadata=TextParser.find_int(r"enqueued\s+(?:\d+\s+)(\d+)"))
    total_enqueued: int = field(metadata=TextParser.find_int(r"enqueued\s+(\d+)"))
    min_dequeued: int = field(metadata=TextParser.find_int(r"dequeued\s+(?:\d+\s+){2}(\d+)"))
    max_dequeued: int = field(metadata=TextParser.find_int(r"dequeued\s+(?:\d+\s+){3}(\d+)"))
    avg_dequeued: int = field(metadata=TextParser.find_int(r"dequeued\s+(?:\d+\s+)(\d+)"))
    total_dequeued: int = field(metadata=TextParser.find_int(r"dequeued\s+(\d+)"))
    min_cycles: float = field(metadata=TextParser.find_float(r"cycles\s+(?:[\d.]+\s+){3}([\d.]+)"))
    max_cycles: float = field(metadata=TextParser.find_float(r"cycles\s+(?:[\d.]+\s+){2}([\d.]+)"))
    avg_cycles: float = field(metadata=TextParser.find_float(r"cycles\s+(?:[\d.]+\s+)([\d.]+)"))
    total_cycles: float = field(metadata=TextParser.find_float(r"cycles\s+([\d.]+)"))
    min_time_us: float = field(
        metadata=TextParser.find_float(r"time \[us\]\s+(?:[\d.]+\s+){3}([\d.]+)")
    )
    max_time_us: float = field(
        metadata=TextParser.find_float(r"time \[us\]\s+(?:[\d.]+\s+){2}([\d.]+)")
    )
    avg_time_us: float = field(
        metadata=TextParser.find_float(r"time \[us\]\s+(?:[\d.]+\s+)([\d.]+)")
    )
    total_time_us: float = field(metadata=TextParser.find_float(r"time \[us\]\s+([\d.]+)"))


@dataclass
class PmdCyclecountResults(CryptodevResults):
    """A parser for PMD cycle count test output."""

    lcore_id: int = field(metadata=TextParser.find_int(r"lcore\s+(?:id.*\n\s+)?(\d+)"))
    buffer_size: int = field(
        metadata=TextParser.find_int(r"Buf(?:.*\n\s+(?:\d+\s+))?(?:fer size:\s+)?(\d+)"),
    )
    burst_size: int = field(
        metadata=TextParser.find_int(r"Burst(?:.*\n\s+(?:\d+\s+){2})?(?: size:\s+)?(\d+)"),
    )
    enqueued: int = field(metadata=TextParser.find_int(r"Enqueued.*\n\s+(?:\d+\s+){3}(\d+)"))
    dequeued: int = field(metadata=TextParser.find_int(r"Dequeued.*\n\s+(?:\d+\s+){4}(\d+)"))
    enqueue_retries: int = field(
        metadata=TextParser.find_int(r"Enq Retries.*\n\s+(?:\d+\s+){5}(\d+)")
    )
    dequeue_retries: int = field(
        metadata=TextParser.find_int(r"Deq Retries.*\n\s+(?:\d+\s+){6}(\d+)")
    )
    cycles_per_operation: float = field(
        metadata=TextParser.find_float(r"Cycles/Op.*\n\s+(?:\d+\s+){7}([\d.]+)")
    )
    cycles_per_enqueue: float = field(
        metadata=TextParser.find_float(r"Cycles/Enq.*\n\s+(?:\d+\s+){7}(?:[\d.]+\s+)([\d.]+)")
    )
    cycles_per_dequeue: float = field(
        metadata=TextParser.find_float(r"Cycles/Deq.*\n\s+(?:\d+\s+){7}(?:[\d.]+\s+){2}([\d.]+)"),
    )


@dataclass
class VerifyResults(CryptodevResults):
    """A parser for verify test output."""

    lcore_id: int = field(metadata=TextParser.find_int(r"lcore\s+(?:id.*\n\s+)?(\d+)"))
    buffer_size: int = field(
        metadata=TextParser.find_int(r"Buf(?:.*\n\s+(?:\d+\s+))?(?:fer size:\s+)?(\d+)"),
    )
    burst_size: int = field(
        metadata=TextParser.find_int(r"Burst(?:.*\n\s+(?:\d+\s+){2})?(?: size:\s+)?(\d+)"),
    )
    enqueued: int = field(metadata=TextParser.find_int(r"Enqueued.*\n\s+(?:\d+\s+){3}(\d+)"))
    dequeued: int = field(metadata=TextParser.find_int(r"Dequeued.*\n\s+(?:\d+\s+){4}(\d+)"))
    failed_enqueued: int = field(
        metadata=TextParser.find_int(r"Failed Enq.*\n\s+(?:\d+\s+){5}(\d+)")
    )
    failed_dequeued: int = field(
        metadata=TextParser.find_int(r"Failed Deq.*\n\s+(?:\d+\s+){6}(\d+)")
    )
    failed_ops: int = field(metadata=TextParser.find_int(r"Failed Ops.*\n\s+(?:\d+\s+){7}(\d+)"))

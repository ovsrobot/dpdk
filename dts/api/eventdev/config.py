# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 University of New Hampshire

"""Module containing types and parameter classes for the dpdk-test-eventdev application."""

from dataclasses import dataclass, field

from api.params import Params, Switch
from api.params.eal import EalParams


@dataclass(slots=True, kw_only=True)
class EventdevParams(EalParams):
    """Parameters for the dpdk-test-eventdev application.

    Attributes:
        test: Name of the test to run.
        wlcores: List of worker lcores.
        stlist: List of scheduled types of the pipeline stages.
        pool_sz: Size of the mbuf mempool.
        nb_eth_queues: Number of Ethernet Rx queues.
        prod_type_ethdev: Use an Ethernet device as the event producer.
    """

    test: str = field(default="pipeline_queue", metadata=Params.long("test"))
    wlcores: str | None = field(default=None, metadata=Params.long("wlcores"))
    stlist: str | None = field(default=None, metadata=Params.long("stlist"))
    pool_sz: int | None = field(default=None, metadata=Params.long("pool_sz"))
    nb_eth_queues: int | None = field(default=None, metadata=Params.long("nb_eth_queues"))
    prod_type_ethdev: Switch = field(default=None, metadata=Params.long("prod_type_ethdev"))

    def __str__(self) -> str:
        """Convert the parameters to a command line string.

        Returns:
            The command line arguments, with underscored option names as the application expects.
        """
        params = Params.__str__(self)
        for name in ("pool_sz", "nb_eth_queues", "prod_type_ethdev"):
            params = params.replace(f"--{name.replace('_', '-')}", f"--{name}")
        return params

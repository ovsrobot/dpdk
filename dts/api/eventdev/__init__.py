# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 University of New Hampshire

"""dpdk-test-eventdev application.

Typical usage example in a TestSuite::

    with Eventdev(num_workers=2, stlist="a"):
        stats = assess_performance_by_packet(packet=packet, duration=5)
"""

from typing import TYPE_CHECKING

from typing_extensions import Self, Unpack

from api.context import get_ctx
from api.eventdev.config import EventdevParams
from api.exception import (
    InteractiveCommandExecutionError,
    SkippedTestException,
)
from api.params import Params
from api.testbed_model.cpu import LogicalCoreCount, LogicalCoreList
from api.testbed_model.virtual_device import VirtualDevice
from framework.remote_session.blocking_app import BlockingApp
from framework.remote_session.dpdk_shell import compute_eal_params

if TYPE_CHECKING:
    from api.params.types import EventdevParamsDict


class Eventdev(BlockingApp[EventdevParams]):
    """Blocking dpdk-test-eventdev application.

    Attributes:
        _app_params: app parameters to pass to dpdk-test-eventdev application
    """

    _app_params: EventdevParams

    def __init__(self, num_workers: int = 1, **app_params: Unpack["EventdevParamsDict"]) -> None:
        """Initialize the eventdev application.

        Args:
            num_workers: number of worker cores to run the application with.
            app_params: The application parameters as keyword arguments.

        Raises:
            ValueError: if the build environment is `None`
            SkippedTestException: if there are not enough cores on one socket
        """
        ctx = get_ctx()
        dpdk = ctx.dpdk.build
        if dpdk is None:
            raise ValueError("No DPDK build environment exists.")
        self._app_path = dpdk.get_app("test-eventdev")

        # One main lcore, one service lcore for the software event scheduler, and the workers.
        num_lcores = num_workers + 2
        try:
            lcores = ctx.dpdk.filter_lcores(
                LogicalCoreCount(cores_per_socket=num_lcores), ctx.local.ascending_cores
            )
        except ValueError as e:
            raise SkippedTestException(
                f"dpdk-test-eventdev needs {num_lcores} cores on one socket: {e}"
            )

        main, service, *workers = lcores
        app_params.setdefault("other_eal_param", Params.from_str(f"-S {service.lcore}"))
        app_params.setdefault("vdevs", [VirtualDevice("event_sw0")])
        app_params.setdefault("lcore_list", LogicalCoreList(lcores))
        app_params.setdefault("wlcores", str(LogicalCoreList(workers)))
        app_params.setdefault("prod_type_ethdev", True)
        params = EventdevParams(**app_params)
        compute_eal_params(params)
        self._num_eth_ports = len(params.allowed_ports or [])
        super().__init__(ctx.sut_node, self._app_path, app_params=params, privileged=True)

    def __enter__(self) -> Self:
        """Start the application and wait until ready.

        Raises:
            InteractiveCommandExecutionError: If there is an error starting the application.

        Returns:
            The started application.
        """
        last_port = self._num_eth_ports - 1
        try:
            return self.wait_until_ready(
                f"Port[{last_port}] using Tx adapter[{last_port}] Configured\x1b[0m"
            )
        except InteractiveCommandExecutionError as e:
            raise e

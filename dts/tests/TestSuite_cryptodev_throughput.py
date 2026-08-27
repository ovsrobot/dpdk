# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""DPDK cryptodev performance test suite.

The main goal of this test suite is to utilize the dpdk-test-cryptodev application to gather
performance metrics for various cryptographic operations supported by DPDK cryptodev-pmd.
It will then compare the results against predefined baseline given in the test_config file to
ensure performance standards are met.
"""

from typing import Any

from api.capabilities import (
    LinkTopology,
    requires_link_topology,
)
from api.cryptodev import Cryptodev
from api.cryptodev.config import (
    AEAD_ALGORITHM_PARAMS,
    AUTHENTICATION_ALGORITHM_PARAMS,
    CIPHER_ALGORITHM_PARAMS,
    AeadAlgName,
    AuthenticationAlgorithm,
    AuthenticationOpMode,
    CipherAlgorithm,
    DeviceType,
    EncryptDecryptSwitch,
    ListWrapper,
    OperationType,
    TestType,
    get_device_from_str,
)
from api.cryptodev.types import (
    CryptodevResults,
)
from api.test import fail, skip, verify
from framework.context import get_ctx
from framework.exception import ConfigurationError, SkippedTestException, TestCaseVerifyError
from framework.test_suite import BaseConfig, TestSuite, crypto_test
from framework.testbed_model.virtual_device import VirtualDevice

config_list: list[dict[str, int | float | str]] = [
    {"buff_size": 64, "Gbps": 1.00},
    {"buff_size": 512, "Gbps": 1.00},
    {"buff_size": 2048, "Gbps": 1.00},
]


class Config(BaseConfig):
    """Performance test metrics.

    Attributes:
        delta_tolerance: The allowed tolerance below a given baseline.
        ops: The total number of operations to run each test case.
        test_combinations: List of test combinations with cipher/auth algorithms and parameters.
    """

    delta_tolerance: float = 0.05
    test_combinations: list[dict[str, Any]] = [
        #: cipher only tests
        {
            "name": "aes-cbc (cipher only)",
            "cipher_algorithm": CipherAlgorithm.aes_cbc.name,
        },
        {
            "name": "aead-docsisbpi (cipher only)",
            "cipher_algorithm": CipherAlgorithm.aes_docsisbpi.name,
        },
        #: authentication only tests
        {
            "name": "sha1-hmac (auth only)",
            "auth_algorithm": AuthenticationAlgorithm.sha1_hmac.name,
            "auth_iv_size": 16,
        },
        #: cipher then auth tests
        {
            "name": "aes-cbc/sha1-hmac (cipher then auth)",
            "cipher_algorithm": CipherAlgorithm.aes_cbc.name,
            "auth_algorithm": AuthenticationAlgorithm.sha1_hmac.name,
            "virtual_device": "crypto_openssl",
        },
        {
            "name": "aes-cbc/sha2-256-hmac (cipher then auth)",
            "cipher_algorithm": CipherAlgorithm.aes_cbc.name,
            "auth_algorithm": AuthenticationAlgorithm.sha2_256_hmac.name,
            "virtual_device": "crypto_openssl",
        },
        {
            "name": "aes-cbc/sha2-256-hmac/digest-16 (cipher then auth)",
            "cipher_algorithm": CipherAlgorithm.aes_cbc.name,
            "auth_algorithm": AuthenticationAlgorithm.sha2_256_hmac.name,
            "digest_size": 16,
        },
        #: aead tests
        {
            "name": "aead-aes-gcm",
            "aead_algorithm": AeadAlgName.aes_gcm.name,
        },
    ]


@requires_link_topology(LinkTopology.NO_LINK)
class TestCryptodevThroughput(TestSuite):
    """DPDK Crypto Device Testing Suite."""

    config: Config

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Raises:
            ConfigurationError: When a test config contains no algorithm to test.
        """
        self.test_combinations: list[dict[str, Any]] = self.config.test_combinations
        self.delta_tolerance: float = self.config.delta_tolerance
        self.ops: int = 10_000_000
        self.device_type: DeviceType | None = get_device_from_str(
            str(get_ctx().sut_node.crypto_device_type)
        )
        self.buffer_sizes: dict[str, ListWrapper] = {}

        # categorize configured tests
        self.cipher_tests: list[dict[str, Any]] = []
        self.auth_tests: list[dict[str, Any]] = []
        self.cipher_then_auth_tests: list[dict[str, Any]] = []
        self.aead_tests: list[dict[str, Any]] = []

        # Filter tests by operation types
        for combination in self.test_combinations:
            self.buffer_sizes[combination["name"]] = ListWrapper(
                [int(run["buff_size"]) for run in combination.get("test_parameters", config_list)]
            )
            is_cipher = "cipher_algorithm" in combination
            is_auth = "auth_algorithm" in combination
            aead = "aead_algorithm" in combination

            if is_cipher and is_auth:
                self.cipher_then_auth_tests.append(combination)
            elif is_cipher:
                self.cipher_tests.append(combination)
            elif is_auth:
                self.auth_tests.append(combination)
            elif aead:
                self.aead_tests.append(combination)
            else:
                raise ConfigurationError(
                    "Each test instance must contain either "
                    "'cipher_algorithm', 'auth_algorithm', or 'aead_algorithm'"
                )

    def _print_and_verify(self, all_results: list[list[dict[str, int | float | str]]]) -> None:
        """Print the given results and verify all results have passed.

        Args:
            all_results: a list of results to print and verify.
        """
        for results in all_results:
            if len(results) > 0:
                self._print_stats(test_vals=results)

        for results in all_results:
            for result in results:
                verify(
                    result["passed"] == "PASS",
                    f"Gbps fell below delta tolerance for test {result['Test Name']}",
                )

    def _print_stats(self, test_vals: list[dict[str, int | float | str]]) -> None:
        """Print the stats of the given test values in a clean format.

        Args:
            test_vals: the testing values to print
        """
        assert len(test_vals) > 0, "test_vals must contain at least one element"

        element_len = len("Delta Tolerance")
        border_len = (element_len + 1) * (len(test_vals[0]) - 1)
        test_name = test_vals[0]["Test Name"]

        print(f"{f'{test_name} Throughput Results'.center(border_len)}\n{'=' * border_len}")
        for k, v in test_vals[0].items():
            if k != "Test Name":
                print(f"|{k.title():<{element_len}}", end="")
        print(f"|\n{'=' * border_len}")

        for test_val in test_vals:
            for k, v in test_val.items():
                if k != "Test Name":
                    print(f"|{v:<{element_len}}", end="")
            print(f"|\n{'=' * border_len}")

    def _create_summary(
        self,
        results: list[CryptodevResults],
        params: list[dict],
        test_name: str,
    ) -> list[dict[str, int | float | str]]:
        """Verify the throughput of the given results against the supplied parameters.

        Args:
            results: The results of the dpdk crypto perf app ran in throughput mode.
            params: The baselines to compare the given results to.
            test_name: The test name to pin to the result summary.

        Returns:
            A summary of throughput statistics for a test and whether the test passed.

        Raises:
            RuntimeError: When there are no baselines for a given result.
        """
        result_list: list[dict[str, int | float | str]] = []

        for result in results:
            # get the corresponding baseline for the current buffer size
            parameters: dict[str, int | float | str] = next(
                filter(
                    lambda x: x["buff_size"] == result.buffer_size,
                    params,
                ),
                {},
            )
            errmsg = (
                f"No test parameters found for {test_name} with buffer size {result.buffer_size}"
            )
            if parameters == {}:
                raise RuntimeError(errmsg)
            test_result = True
            expected_gbps = parameters["Gbps"]
            measured_delta = abs(
                round((getattr(result, "gbps") - expected_gbps) / expected_gbps, 5)
            )
            # result did not meet the given Gbps parameter, check if within delta.
            if getattr(result, "gbps") < expected_gbps:
                if self.delta_tolerance < measured_delta:
                    test_result = False

            result_list.append(
                {
                    "Test Name": test_name,
                    "Buffer Size": parameters["buff_size"],
                    "Gbps delta": measured_delta,
                    "delta tolerance": self.delta_tolerance,
                    "Gbps": getattr(result, "gbps"),
                    "Gbps target": expected_gbps,
                    "passed": "PASS" if test_result else "FAIL",
                }
            )
        return result_list

    @crypto_test
    def cipher_only_tests(self) -> None:
        """Cipher only cryptography device tests.

        Steps:
            * Run dpdk-test-crypto-perf application with configured arguments in cipher only mode.
        Verify:
            * The reported Gbps is within a defined tolerance of a given baseline.
        """

        def test(encrypt: EncryptDecryptSwitch) -> list[dict[str, int | float | str]]:
            """Run a configured throughput test with the given encryption.

            Args:
                encrypt: The cipher encryption mode to run throughput testing on.

            Returns:
                The generated summary or an empty list if a test is skipped.
            """
            cipher_params = CIPHER_ALGORITHM_PARAMS[
                CipherAlgorithm[combination["cipher_algorithm"]]
            ]
            is_vdev = "virtual_device" in combination
            app = Cryptodev(
                ptest=TestType.throughput,
                devtype=self.device_type,
                optype=OperationType.cipher_only,
                cipher_algo=CipherAlgorithm[combination["cipher_algorithm"]],
                cipher_op=encrypt,
                cipher_key_sz=combination.get("cipher_key_size", cipher_params["key_size"]),
                cipher_iv_sz=combination.get("cipher_iv_size", cipher_params["iv_size"]),
                digest_sz=combination.get("digest_size", 0),
                total_ops=combination.get("ops", self.ops),
                buffer_sz=self.buffer_sizes[combination.get("name", "custom_test")],
            )
            if is_vdev:
                app.update_params(
                    vdevs=[VirtualDevice(combination["virtual_device"])],
                    devtype=get_device_from_str(combination["virtual_device"]),
                )

            self._logger.info(f"Running configured test: {test_name} in {encrypt} mode")
            try:
                return self._create_summary(
                    results=app.run_app(num_vfs=0 if is_vdev else 1),
                    params=combination.get("test_parameters", config_list),
                    test_name=f"{combination.get('name', 'unnamed-test')} - {encrypt}",
                )
            # A skip on one test will stop the execution of all tests, return empty summary.
            except SkippedTestException as e:
                self._logger.error(f"test {test_name} skipped: {str(e)}")
                return []

        test_cases_skipped: int = 0
        failed: bool = False
        reason: str = ""
        # Execute all cipher only tests and verify
        for combination in self.cipher_tests:
            test_name = combination.get("name", "unnamed_test")
            combination_results = [(test(mode)) for mode in EncryptDecryptSwitch]
            if all(result == [] for result in combination_results):
                test_cases_skipped += 1
            else:
                try:
                    self._print_and_verify(combination_results)
                except TestCaseVerifyError as e:
                    failed = True
                    reason = f"{reason}\n{str(e)}" if reason else str(e)
        if failed:
            fail(reason)
        if test_cases_skipped == len(self.cipher_tests):
            skip("All configured test cases skipped.")

    @crypto_test
    def auth_only_tests(self) -> None:
        """Authentication cryptography device tests.

        Steps:
            * Run dpdk-test-crypto-perf application with configured parameters in authentication
                only moode.
        Verify:
            * The resulting Gbps is within a delta tolerance of a provided baseline.
        """

        def test(op_mode: AuthenticationOpMode) -> list[dict[str, int | float | str]]:
            """Run a configured throughput test with the given authentication mode.

            Args:
                op_mode: The authentication op mode to run testing in.

            Returns:
                The generated summary or an empty list if a test is skipped.
            """
            auth_params = AUTHENTICATION_ALGORITHM_PARAMS[
                AuthenticationAlgorithm[combination["auth_algorithm"]]
            ]
            is_vdev: bool = "virtual_device" in combination
            app = Cryptodev(
                ptest=TestType.throughput,
                devtype=self.device_type,
                optype=OperationType.auth_only,
                auth_algo=AuthenticationAlgorithm[combination["auth_algorithm"]],
                auth_op=op_mode,
                auth_key_sz=combination.get("auth_key_size", auth_params["key_size"]),
                auth_iv_sz=combination.get("auth_iv_size", auth_params["iv_size"]),
                total_ops=combination.get("ops", self.ops),
                digest_sz=combination.get("digest_size", 0),
                buffer_sz=self.buffer_sizes[combination["name"]],
            )
            if is_vdev:
                app.update_params(
                    vdevs=[VirtualDevice(combination["virtual_device"])],
                    devtype=get_device_from_str(combination["virtual_device"]),
                )

            self._logger.info(f"Running configured test: {test_name} in {op_mode} mode")
            try:
                return self._create_summary(
                    results=app.run_app(num_vfs=0 if is_vdev else 1),
                    params=combination.get("test_parameters", config_list),
                    test_name=f"{combination.get('name', 'unnamed-test')} - {op_mode}",
                )
            # A skip on one test will stop the execution of all tests, return empty summary.
            except SkippedTestException as e:
                self._logger.error(f"failed to run test {test_name}: {str(e)}")
                return []

        test_cases_skipped: int = 0
        failed: bool = False
        reason: str = ""
        # Execute all auth only tests and verify
        for combination in self.auth_tests:
            test_name = combination.get("name", "unnamed_test")
            combination_results = [(test(AuthenticationOpMode.generate))]
            if all(result == [] for result in combination_results):
                test_cases_skipped += 1
            else:
                try:
                    self._print_and_verify(combination_results)
                except TestCaseVerifyError as e:
                    failed = True
                    reason = f"{reason}\n{str(e)}" if reason else str(e)
        if failed:
            fail(reason)
        if test_cases_skipped == len(self.auth_tests):
            skip("All configured test cases skipped.")

    @crypto_test
    def aead_test(self) -> None:
        """Aead cryptography test.

        Steps:
            * Run dpdk-test-crypto-perf application with configured parameters in aead mode.
        Verify:
            * The resulting Gbps is within a delta tolerance of a given baseline.
        """

        def test() -> list[dict[str, int | float | str]]:
            """Execute the dpdk-test-crypto application and verify.

            Args:
                encrypt: The authentication operation mode to run the cryptodev application in.

            Returns:
                The generated summary or an empty list if a test is skipped.
            """
            is_vdev: bool = "virtual_device" in combination
            aead_params = AEAD_ALGORITHM_PARAMS[AeadAlgName[combination["aead_algorithm"]]]
            app = Cryptodev(
                ptest=TestType.throughput,
                devtype=self.device_type,
                optype=OperationType.aead,
                aead_algo=AeadAlgName[combination["aead_algorithm"]],
                aead_op=combination.get("aead_op", EncryptDecryptSwitch.encrypt),
                aead_key_sz=combination.get("aead_key_size", aead_params["key_size"]),
                aead_iv_sz=combination.get("aead_iv_size", aead_params["iv_size"]),
                aead_aad_sz=combination.get("aead_size", aead_params["aad_size"]),
                digest_sz=combination.get("digest_size", aead_params["digest_size"]),
                total_ops=combination.get("ops", self.ops),
                buffer_sz=self.buffer_sizes[combination["name"]],
            )
            if is_vdev:
                app.update_params(
                    vdevs=[VirtualDevice(combination["virtual_device"])],
                    devtype=get_device_from_str(combination["virtual_device"]),
                )
            if combination.get("aead_op", None) == EncryptDecryptSwitch.decrypt:
                app.update_params(
                    out_of_place=combination.get("out_of_place", True),
                )

            self._logger.info(f"Running configured test: {test_name}")
            try:
                return self._create_summary(
                    results=app.run_app(num_vfs=0 if is_vdev else 1),
                    params=combination.get("test_parameters", config_list),
                    test_name=f"{combination.get('name', 'unnamed-test')}",
                )
            # Exceptions will stop the execution of all tests, return an empty result and continue.
            except SkippedTestException as e:
                self._logger.error(f"failed to run test {test_name}: {str(e)}")
                return []

        test_cases_skipped: int = 0
        failed: bool = False
        reason: str = ""
        # Execute all aead tests and verify
        for combination in self.aead_tests:
            test_name = combination.get("name", "unnamed_test")
            combination_results = [test()]
            if all(result == [] for result in combination_results):
                test_cases_skipped += 1
            else:
                try:
                    self._print_and_verify(combination_results)
                except TestCaseVerifyError as e:
                    failed = True
                    reason = f"{reason}\n{str(e)}" if reason else str(e)
        if failed:
            fail(reason)
        if test_cases_skipped == len(self.aead_tests):
            skip("All configured test cases skipped.")

    @crypto_test
    def cipher_and_auth_tests(self) -> None:
        """Cipher and Authentication tests.

        Steps:
            * Run dpdk-test-crypto-perf application in cipher then authentication mode
        Verify:
            * The resulting Gbps is within a delta tolerance of a given baseline.
        """

        def test(
            encrypt: EncryptDecryptSwitch, op_mode: AuthenticationOpMode
        ) -> list[dict[str, int | float | str]]:
            """Execute the dpdk-test-crypto application and verify.

            Args:
                encrypt: The cipher encryption mode to run throughput testing in.
                op_mode: The authentication operation mode to run the cryptodev application in.

            Returns:
                The generated summary or an empty list if a test is skipped.
            """
            is_vdev: bool = "virtual_device" in combination
            cipher_params = CIPHER_ALGORITHM_PARAMS[
                CipherAlgorithm[combination["cipher_algorithm"]]
            ]
            auth_params = AUTHENTICATION_ALGORITHM_PARAMS[
                AuthenticationAlgorithm[combination["auth_algorithm"]]
            ]
            app = Cryptodev(
                ptest=TestType.throughput,
                devtype=self.device_type,
                optype=OperationType.aead,
                cipher_algo=CipherAlgorithm[combination["cipher_algorithm"]],
                cipher_op=encrypt,
                cipher_key_sz=combination.get("cipher_key_size", cipher_params["key_size"]),
                cipher_iv_sz=combination.get("cipher_iv_size", cipher_params["iv_size"]),
                auth_algo=AuthenticationAlgorithm[combination["auth_algorithm"]],
                auth_op=op_mode,
                auth_key_sz=combination.get("auth_key_size", auth_params["key_size"]),
                auth_iv_sz=combination.get("auth_iv_size", auth_params["iv_size"]),
                total_ops=combination.get("ops", self.ops),
                digest_sz=combination.get("digest_size", 0),
                buffer_sz=self.buffer_sizes[combination["name"]],
            )
            if is_vdev:
                app.update_params(
                    vdevs=[VirtualDevice(combination["virtual_device"])],
                    devtype=get_device_from_str(combination["virtual_device"]),
                )

            self._logger.info(f"Running configured test: {test_name} in {encrypt} mode")
            try:
                return self._create_summary(
                    results=app.run_app(num_vfs=0 if is_vdev else 1),
                    params=combination.get("test_parameters", config_list),
                    test_name=f"{combination.get('name', 'unnamed-test')} - {encrypt}",
                )
            # Exceptions will stop the execution of all tests, return an empty result and continue.
            except SkippedTestException as e:
                self._logger.error(f"failed to run test {test_name}: {str(e)}")
                return []

        test_cases_skipped: int = 0
        failed: bool = False
        reason: str = ""
        # Execute all cipher_then_auth tests and verify
        for combination in self.cipher_then_auth_tests:
            test_name = combination.get("name", "unnamed_test")
            combination_results = [
                test(mode, AuthenticationOpMode.generate) for mode in EncryptDecryptSwitch
            ]
            if all(result == [] for result in combination_results):
                test_cases_skipped += 1
            else:
                try:
                    self._print_and_verify(combination_results)
                except TestCaseVerifyError as e:
                    failed = True
                    reason = f"{reason}\n{str(e)}" if reason else str(e)
        if failed:
            fail(reason)
        if test_cases_skipped == len(self.cipher_then_auth_tests):
            skip("All configured test cases skipped.")

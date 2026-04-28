# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 University of New Hampshire

"""DPDK cryptodev verify test suite.

The main goal of this test suite is to utilize the verify mode of dpdk-test-crypto application
to ensure functional correctness for various cryptographic operations supported by DPDK
cryptodev-pmd.
"""

from api.capabilities import (
    LinkTopology,
    requires_link_topology,
)
from api.cryptodev import Cryptodev
from api.cryptodev.config import (
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
from api.test import skip, verify
from framework.context import get_ctx
from framework.test_suite import BaseConfig, TestSuite, crypto_test
from framework.testbed_model.virtual_device import VirtualDevice

TOTAL_OPS = 10_000_000
TEST_FILE = "/path/to/test/vector/file.data"
config_list = [64, 512, 1024, 2048]


class Config(BaseConfig):
    """Performance test metrics.

    Attributes:
        delta_tolerance: The allowed tolerance below a given baseline.
        throughput_test_parameters: The test parameters to use in the test suite.
    """

    delta_tolerance: float = 0.05

    verify_test_parameters: dict[str, list[int]] = {
        "aesni_mb_vdev": config_list,
        "openssl_vdev": config_list,
        "sha1_hmac_buff_32": config_list,
    }


@requires_link_topology(LinkTopology.NO_LINK)
class TestCryptodevVerify(TestSuite):
    """DPDK Crypto Device Testing Suite."""

    config: Config

    def set_up_suite(self) -> None:
        """Set up the test suite."""
        self.verify_test_parameters: dict[str, list[int]] = self.config.verify_test_parameters
        self.delta_tolerance: float = self.config.delta_tolerance
        self.device_type: DeviceType | None = get_device_from_str(
            str(get_ctx().sut_node.crypto_device_type)
        )
        self.buffer_sizes = {}

        for k, v in self.verify_test_parameters.items():
            self.buffer_sizes[k] = ListWrapper(v)

    def _print_stats(self, test_vals: list[dict[str, int | float]]) -> None:
        element_len = len("Delta Tolerance")
        border_len = (element_len + 1) * (len(test_vals[0]))

        print(f"{'Verify Results'.center(border_len)}\n{'=' * border_len}")
        for k, v in test_vals[0].items():
            print(f"|{k.title():<{element_len}}", end="")
        print(f"|\n{'='*border_len}")

        for test_val in test_vals:
            for k, v in test_val.items():
                print(f"|{v:<{element_len}}", end="")
            print(f"|\n{'='*border_len}")

    def _verify_output(
        self,
        results: list[CryptodevResults],
        key: str,
    ) -> list[dict[str, int | float]]:
        result_list: list[dict[str, int | float]] = []
        if key not in self.verify_test_parameters:
            skip(f"{key} test not configured")

        results_list = []
        passed = True
        for result in results:
            if getattr(result, "failed_enqueue") / TOTAL_OPS > self.delta_tolerance:
                passed = False
            if getattr(result, "failed_dequeue") / TOTAL_OPS > self.delta_tolerance:
                passed = False
            if getattr(result, "failed_ops") / TOTAL_OPS > self.delta_tolerance:
                passed = False
            results_list.append(
                {
                    "Failed Enqueue": getattr(result, "failed_enqueue"),
                    "Failed Dequeue": getattr(result, "failed_dequeue"),
                    "Failed Operations": getattr(result, "failed_ops"),
                    "Delta Tolerance": self.delta_tolerance,
                    "Passed": passed,
                }
            )
        return result_list

    @crypto_test
    def aesni_mb_vdev(self) -> None:
        """aesni_mb_vdev test.

        Steps:
            * Create a cryptodev instance with aesni_mb virtual device and provided buffer sizes.
        Verify:
            * The aes_cbc cipher and sha1_hmac authentication algorithms are working as expected
                with the dpdk-test-crypto application.
        """
        if "aesni_mb_vdev" not in self.verify_test_parameters:
            skip("test not configured")
        app = Cryptodev(
            vdevs=[VirtualDevice("crypto_aesni_mb0")],
            ptest=TestType.verify,
            test_file=TEST_FILE,
            test_name="sha1_hmac_buff_32",
            devtype=DeviceType.crypto_aesni_mb,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.aes_cbc,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=32,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.sha1_hmac,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=12,
            burst_sz=32,
            total_ops=TOTAL_OPS,
            buffer_sz=self.buffer_sizes["aesni_mb_vdev"],
        )
        results = self._verify_output(app.run_app(), "aesni_mb_vdev")
        self._print_stats(results)
        for result in results:
            verify(result["passed"] == "PASS", "Gbps fell below delta tolerance")

    @crypto_test
    def openssl_vdev(self) -> None:
        """Openssl vdev test.

        Steps:
            * Create a cryptodev instance with openssl virtual device and provided buffer sizes.
        Verify:
            * The aes_cbc cipher and sha1_hmac authentication algorithms are working as expected
                with the dpdk-test-crypto application.

        Raises:
            SkippedTestException: When configuration is not provided.
        """
        if "openssl_vdev" not in self.verify_test_parameters:
            skip("test not configured")
        app = Cryptodev(
            vdevs=[VirtualDevice("crypto_openssl0")],
            ptest=TestType.verify,
            test_file=TEST_FILE,
            test_name="aes_gcm_buff_32",
            devtype=DeviceType.crypto_openssl,
            optype=OperationType.aead,
            aead_algo=AeadAlgName.aes_gcm,
            aead_op=EncryptDecryptSwitch.encrypt,
            aead_key_sz=16,
            aead_aad_sz=16,
            aead_iv_sz=12,
            digest_sz=16,
            burst_sz=32,
            buffer_sz=self.buffer_sizes["aesni_mb"],
            total_ops=TOTAL_OPS,
        )
        results = self._verify_output(app.run_app(), "openssl_vdev")
        self._print_stats(results)
        for result in results:
            verify(result["passed"] == "PASS", "Gbps fell below delta tolerance")

    @crypto_test
    def sha1_hmac_buff_32(self) -> None:
        """aes_cbc test.

        Steps:
            * Create a cryptodev instance with provided device type and buffer sizes.
        Verify:
            * The aes_cbc cipher and sha1_hmac authentication algorithms are working as expected
                with the dpdk-test-crypto application.

        Raises:
            SkippedTestException: When configuration is not provided.
        """
        if "sha1_hmac_buff_32" not in self.verify_test_parameters:
            skip("test not configured")
        app = Cryptodev(
            ptest=TestType.verify,
            test_file=TEST_FILE,
            test_name="sha1_hmac_buff_32",
            devtype=self.device_type,
            optype=OperationType.aead,
            cipher_algo=CipherAlgorithm.aes_cbc,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=32,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.sha1_hmac,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=20,
            burst_sz=32,
            buffer_sz=self.buffer_sizes["sha1_hmac_buff_32"],
            total_ops=TOTAL_OPS,
        )
        results = self._verify_output(app.run_app(), "sha1_hmac_buff_32")
        self._print_stats(results)
        for result in results:
            verify(result["passed"] == "PASS", "Gbps fell below delta tolerance")

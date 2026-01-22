# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""DPDK cryptodev performance test suite.

The main goal of this testsuite is to utilize the dpdk-test-cryptodev application to gather
performance metrics for various cryptographic operations supported by DPDK cryptodev-pmd.
It will then compare the results against predefined baseline defined in the test_config file to
ensure performance standards are met.
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
)
from api.cryptodev.types import (
    CryptodevResults,
)
from api.test import verify
from framework.test_suite import BaseConfig, TestSuite, crypto_test


class Config(BaseConfig):
    """Performance test metrics."""

    common_params: dict[str, int | float] = {
        "Gbps Delta": 0.05,
    }
    throughput_test_parameters: list[dict[str, int | float | str]] = [
        {
            **common_params,
            "buff_size": 64,
            "mops": 9.85,
            "gbps": 2.49,
        },
        {
            **common_params,
            "buff_size": 128,
            "mops": 4.83,
            "gbps": 4.95,
        },
        {
            **common_params,
            "buff_size": 256,
            "mops": 4.77,
            "gbps": 9.76,
        },
        {
            **common_params,
            "buff_size": 512,
            "mops": 4.52,
            "gbps": 18.52,
        },
        {
            **common_params,
            "buff_size": 1048,
            "mops": 3.77,
            "gbps": 30.87,
        },
        {
            **common_params,
            "buff_size": 2048,
            "mops": 2.49,
            "gbps": 40.86,
        },
    ]


@requires_link_topology(LinkTopology.NO_LINK)
class TestCryptodevThroughput(TestSuite):
    """DPDK Crypto Device Testing Suite."""

    config: Config
    unsupported_cryptodevs: list[DeviceType] = []

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup: Retrieve application parameters from the configuration.
        """
        self.throughput_test_parameters: list[dict[str, int | float | str]] = (
            self.config.throughput_test_parameters
        )
        self.buffer_sizes = ListWrapper(
            [int(run["buff_size"]) for run in self.throughput_test_parameters]
        )

    def _print_stats(self, test_vals) -> None:
        element_len = len("Gbps Target")
        border_len = (element_len + 1) * (len(test_vals[0].items()))
        print(f"{'Throughput Results'.center(border_len)}")
        print("=" * border_len)
        for k, v in test_vals[0].items():
            print(f"|{k.title():<{element_len}}", end="")
        print(f"|\n{'='*border_len}")
        for test_val in test_vals:
            for k, v in test_val.items():
                print(f"|{v:<{element_len}}", end="")
            print(f"|\n{'='*border_len}")

    def _verify_throughput(
        self, results: list[CryptodevResults]
    ) -> list[dict[str, int | float | str]]:
        result_list = []
        for result in results:
            result_dict = {}
            parameters = list(
                filter(
                    lambda x: x["buff_size"] == result.buffer_size,
                    self.throughput_test_parameters,
                )
            )[0]
            test_result = True
            for key, target_val in parameters.items():
                if key == "buff_size" or key == "delta":
                    result_dict[key] = target_val
                    continue
                if target_val > getattr(result, key):
                    delta = round((1 - (getattr(result, key) / target_val)), 5)
                    if delta > parameters["delta"]:
                        test_result = False
                else:
                    delta = round((1 - target_val / getattr(result, key)), 5)
                result_dict[key] = getattr(result, key)
                result_dict[f"{key} target"] = target_val
                result_dict[f"{key} delta"] = delta
            result_dict["passed"] = "PASS" if test_result else "FAIL"
            result_list.append(result_dict)
        return result_list

    @crypto_test
    def qat_cipher_then_auth_aes_cbc_encrypt(self) -> None:
        """Test throughput on crypto_qat device type with aes-cbc and sha2-256-hmac algorithms.

        Steps:
            * Create a Cryptodev application instance with crypto_qat devtype
                and cipher_then_auth operation with aes-cbc and sha2-256-hmac algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.aes_cbc,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.sha2_256_hmac,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=32,
            total_ops=30_000_000,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
        )
        results = self._verify_throughput(app.run_app(numvfs=0))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"""Gbps was {result["gbps delta"]} below baseline
                \nMOps was {result["mops delta"]} below baseline""",
            )

    @crypto_test
    def qat_aead_aes_gcm_encrypt(self) -> None:
        """Test throughput on a crypto_qat device type with aes-gcm algorithm.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and aead operation with aes-gcm algorithm
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.aead,
            aead_aad_sz=16,
            aead_key_sz=16,
            aead_iv_sz=12,
            aead_op=EncryptDecryptSwitch.encrypt,
            aead_algo=AeadAlgName.aes_gcm,
            digest_sz=16,
            total_ops=30_000_000,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
        )
        results = self._verify_throughput(app.run_app(numvfs=1))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"Gbps and MOps were {result["gbps delta"]} below baseline",
            )

    @crypto_test
    def qat_cipher_aes_docsisbpi_decrypt(self) -> None:
        """Test throughput on a crypto_qat devtype with aes-docsibpi algorithm.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_only operation with aes-docsibpi algorithm
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_only,
            cipher_algo=CipherAlgorithm.aes_docsisbpi,
            cipher_op=EncryptDecryptSwitch.decrypt,
            cipher_key_sz=32,
            cipher_iv_sz=16,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
            total_ops=30_000_000,
        )
        results = self._verify_throughput(app.run_app(numvfs=1))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"Gbps and MOps were {result["gbps delta"]} below baseline",
            )

    @crypto_test
    def qat_cipher_aes_docsisbpi_encrypt(self) -> None:
        """Test throughput on a crypto_qat device type with aes-docsibpi algorithm.

        Steps:
            * Create a Cryptodev application instance with crypto_qat device
                and cipher_only operation with aes-docsibpi algorithm
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_only,
            cipher_algo=CipherAlgorithm.aes_docsisbpi,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=32,
            cipher_iv_sz=16,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
            total_ops=30_000_000,
        )
        results = self._verify_throughput(app.run_app(numvfs=3))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"Gbps and MOps were {result["gbps delta"]} below baseline",
            )

    @crypto_test
    def qat_cipher_then_auth_kasumi_f8_encrypt(self) -> None:
        """Test throughput on a crypto_qat device type with kasumi-f8 and kasumi-f9 algorithms.

        Steps:
            * Create a Cryptodev application instance with crypto_qat device
                and cipher_then_auth operation with kasumi-f8 and kasumi-f9 algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.kasumi_f8,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=8,
            auth_algo=AuthenticationAlgorithm.kasumi_f9,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=16,
            digest_sz=4,
            total_ops=30_000_000,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
        )
        results = self._verify_throughput(app.run_app(numvfs=6))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"Gbps and MOps were {result["gbps delta"]} below baseline",
            )

    @crypto_test
    def qat_cipher_then_auth_snow3g_uea2_encrpyt(self) -> None:
        """Test throughput on a crypto_qat device type with snow3g-uea2 and snow3g-uia2 algorithms.

        Steps:
            * Create a Cryptodev application instance with crypto_qat device
                and cipher_then_auth operation with snow3g-uea2 and snow3g-uia2 algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.snow3g_uea2,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.snow3g_uia2,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=16,
            auth_iv_sz=16,
            digest_sz=4,
            total_ops=30_000_000,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
        )
        results = self._verify_throughput(app.run_app(numvfs=12))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"Gbps and MOps were {result["gbps delta"]} below baseline",
            )

    @crypto_test
    def qat_cipher_then_auth_zuc_eea3_encrypt(self) -> None:
        """Test throughput on a crypto_qat device type with zuc-eea3 and zuc-eia3 algorithms.

        Steps:
            * Create a Cryptodev application instance with crypto_qat device
                and cipher_then_auth operation with zuc-eea3 and zuc-eia3 algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined baseline
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.zuc_eea3,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.zuc_eia3,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=16,
            auth_iv_sz=16,
            digest_sz=4,
            total_ops=30_000_000,
            burst_sz=32,
            buffer_sz=self.buffer_sizes,
        )
        results = self._verify_throughput(app.run_app(numvfs=12))
        self._print_stats(results)
        for result in results:
            verify(
                result["passed"] == "PASS",
                f"Gbps and MOps were {result["gbps delta"]} below baseline",
            )

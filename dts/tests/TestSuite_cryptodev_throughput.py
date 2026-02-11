# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire
"""DPDK cryptodev performance test suite.

The main goal of this testsuite is to utilize the dpdk-test-cryptodev application to gather
performance metrics for various cryptographic operations supported by DPDK cryptodev-pmd.
It will then compare the results against predefined thresholds defined in the test_config file to
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
from framework.test_suite import BaseConfig, TestSuite, func_test
from framework.testbed_model.virtual_device import VirtualDevice


class Config(BaseConfig):
    """Performance test metrics."""

    throughput_test_parameters: dict[str, int | float] = {
        "enqueued": 0,
        "dequeued": 0,
        "failed_enqueued": 0,
        "failed_dequeued": 0,
        "mops": 0,
        "gbps": 0,
        "cycles_per_buffer": 0,
    }


@requires_link_topology(LinkTopology.NO_LINK)
class TestCryptodevThroughput(TestSuite):
    """DPDK Crypto Device Testing Suite.

    This test suite is comprised of 8 test cases:
    1. verify throughput metrics of openssl encrypt virtual device with aes-gcm algorithm
    2. verify throughput metrics of QAT device encrypt with aes-cbc cipher algorithm and sha256-hmac
        auth algorithm
    3. verify throughput metrics of QAT device encrypt with aes-gcm aead algorithm
    4. verify throughput metrics of QAT device decrypt with aes-docsibpi cipher algorithm
    5. verify throughput metrics of QAT device encrypt with aes-docsibpi cipher algorithm
    6. verify throughput metrics of QAT device encrypt with kasumi-f8 cipher algorithm and kasumi-f9
        auth algorithm
    7. verify throughput metrics of QAT device encrypt with snow3g-uea2 cipher algorithm and
        snow3g-uia2 auth algorithm
    8. verify throughput metrics of QAT device encrypt with zuc-eea3 cipher algorithm and zuc-eia3
        auth algorithm
    """

    config: Config
    unsupported_cryptodevs: list[DeviceType] = []

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup: Retrieve application parameters from the configuration.
        """
        self.throughput_test_parameters = self.config.throughput_test_parameters

    def _verify_throughput(self, results: list[CryptodevResults]) -> None:
        """Verify throughput results against predefined thresholds.

        Arguments:
            results: The results containing throughput metrics to verify.
        """
        for result in results:
            for key, value in self.throughput_test_parameters.items():
                result_value = getattr(result, key, None)
                if result_value is not None:
                    verify(
                        result_value > value,
                        f"Throughput metric {key} is below the threshold: {result_value} < {value}",
                    )

    def _run_app(self, app: Cryptodev) -> None:
        """Run the given cryptodev application, print statistics, and verify throughput.

        Arguments:
            app: The cryptodev application to run and collect data on.

        Raises:
            SkippedTestException: If the cryptodev application cannot be run with the given
                configuration.
        """
        print("UNSUPPORTED CRYPTO DEVS:", self.unsupported_cryptodevs)
        try:
            results: list[CryptodevResults] = app.run_app()
        except Exception as e:
            if "devtype" in str(e):
                self.unsupported_cryptodevs.append(app._app_params["devtype"])
            print(f"Skipping test: {e}")
            raise
        app.print_stats(results)
        self._verify_throughput(results)

    @func_test
    def openssl_aead_aes_gcm_encrypt(self) -> None:
        """Basic test to run on all NICs with openssl virtual device.

        Steps:
            * Create a Cryptodev application instance with OpenSSL virtual device
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
        """
        app = Cryptodev(
            vdevs=[VirtualDevice("crypto_openssl")],
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_openssl,
            aead_algo=AeadAlgName.aes_gcm,
            aead_aad_sz=16,
            aead_key_sz=16,
            aead_iv_sz=16,
            digest_sz=16,
            aead_op=EncryptDecryptSwitch.encrypt,
            optype=OperationType.aead,
            total_ops=10_000_000,
        )
        self._run_app(app)

    @func_test
    def qat_cipher_then_auth_aes_cbc_encrypt(self) -> None:
        """Test throughput on a QAT device with aes-cbc and sha2-256-hmac algorithms.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with aes-cbc and sha2-256-hmac algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def qat_aead_aes_gcm_encrypt(self) -> None:
        """Test throughput on a QAT device with aes-gcm algorithm.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and aead operation with aes-gcm algorithm
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def qat_cipher_aes_docsisbpi_decrypt(self) -> None:
        """Test throughput on a QAT device with aes-docsibpi algorithm.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_only operation with aes-docsibpi algorithm
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            buffer_sz=ListWrapper([40, 64, 70, 128, 256, 512, 1024, 2048]),
            total_ops=10_000_000,
        )
        self._run_app(app)

    @func_test
    def qat_cipher_aes_docsisbpi_encrypt(self) -> None:
        """Test throughput on a QAT device with aes-docsibpi algorithm.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_only operation with aes-docsibpi algorithm
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            buffer_sz=ListWrapper([40, 64, 70, 128, 256, 512, 1024, 2048]),
            total_ops=10_000_000,
        )
        self._run_app(app)

    @func_test
    def qat_cipher_then_auth_kasumi_f8_encrypt(self) -> None:
        """Test throughput on a QAT device with kasumi-f8 and kasumi-f9 algorithms.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with kasumi-f8 and kasumi-f9 algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def qat_cipher_then_auth_snow3g_uea2_encrpyt(self) -> None:
        """Test throughput on a QAT device with snow3g-uea2 and snow3g-uia2 algorithms.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with snow3g-uea2 and snow3g-uia2 algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def qat_cipher_then_auth_zuc_eea3_encrypt(self) -> None:
        """Test throughput on a QAT device with zuc-eea3 and zuc-eia3 algorithms.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with zuc-eea3 and zuc-eia3 algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
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
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def a_wrong_devtype(self) -> None:
        """Test throughput on a QAT device.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with aes-cbc and sha2-256-hmac algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_mvsam,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.aes_cbc,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.sha2_256_hmac,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=32,
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def anotha_one(self) -> None:
        """Test throughput on a QAT device.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with aes-cbc and sha2-256-hmac algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_zuc,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.aes_ecb,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.sha2_256_hmac,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=32,
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def wrong_auth_alg(self) -> None:
        """Test throughput on a QAT device.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with aes-cbc and sha2-256-hmac algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.aes_cbc,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.md5,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=32,
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

    @func_test
    def wrong_auth_and_cipher_alg(self) -> None:
        """Test throughput on a QAT device.

        Steps:
            * Create a Cryptodev application instance with QAT device
                and cipher_then_auth operation with aes-cbc and sha2-256-hmac algorithms
            * Run the application and gather throughput statistics

        Verify:
            * Throughput results meet predefined thresholds
        """
        app = Cryptodev(
            ptest=TestType.throughput,
            devtype=DeviceType.crypto_qat,
            optype=OperationType.cipher_then_auth,
            cipher_algo=CipherAlgorithm.aes_ecb,
            cipher_op=EncryptDecryptSwitch.encrypt,
            cipher_key_sz=16,
            cipher_iv_sz=16,
            auth_algo=AuthenticationAlgorithm.md5,
            auth_op=AuthenticationOpMode.generate,
            auth_key_sz=64,
            digest_sz=32,
            total_ops=10_000_000,
            burst_sz=32,
            buffer_sz=ListWrapper([64, 128, 256, 512, 1024, 2048]),
        )
        self._run_app(app)

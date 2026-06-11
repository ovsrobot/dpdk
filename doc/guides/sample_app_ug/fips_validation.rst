..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

Federal Information Processing Standards (FIPS) CryptoDev Validation
====================================================================

Overview
--------

This application parses and performs symmetric cryptography computations
using test vectors from the NIST Cryptographic Algorithm Validation Program
(CAVP) and Automated Crypto Validation Protocol (ACVP).

Federal Information Processing Standards (FIPS) are publicly announced standards
developed by the United States federal government for use in computer systems by
non-military agencies and government contractors.

For an algorithm implementation to be listed on a cryptographic module
validation certificate as an Approved security function, the algorithm
implementation must meet all the requirements of FIPS 140-2 (in case of CAVP)
and FIPS 140-3 (in case of ACVP) and must successfully complete the
cryptographic algorithm validation process.


Limitations
-----------

CAVP
----

* The version of request file supported is ``CAVS 21.0``.
* If the header comment in a ``.req`` file does not contain an algorithm tag
  (i.e., ``AES``, ``TDES``, ``GCM``), you must manually add it to the header
  comment, for example::

      # VARIABLE KEY - KAT for CBC / # TDES VARIABLE KEY - KAT for CBC

* The application does not supply the test vectors. Users must obtain the
  test vector files from the `CAVP
  <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-
  program/block-ciphers>`_ website. To obtain the ``.req`` files, you need to
  contact a representative from the NIST website and pay for the ``.req`` files.
  The ``.rsp`` files from the site can be used to validate and compare with
  the ``.rsp`` files created by the FIPS application.

* Supported test vectors
    * AES-CBC (128,192,256) - GFSbox, KeySbox, MCT, MMT
    * AES-GCM (128,192,256) - EncryptExtIV, Decrypt
    * AES-CCM (128) - VADT, VNT, VPT, VTT, DVPT
    * AES-CMAC (128) - Generate, Verify
    * HMAC (SHA1, SHA224, SHA256, SHA384, SHA512)
    * TDES-CBC (1 Key, 2 Keys, 3 Keys) - MMT, Monte, Permop, Subkey, Varkey,
      VarText

ACVP
----

* The application does not supply the test vectors. Users must
  obtain the test vector files from `ACVP  <https://pages.nist.gov/ACVP>`_
  website.
* Supported test vectors
    * AES-CBC (128,192,256) - AFT, MCT
    * AES-GCM (128,192,256) - AFT
    * AES-CCM (128,192,256) - AFT
    * AES-CMAC (128,192,256) - AFT
    * AES-CTR (128,192,256) - AFT, CTR
    * AES-GMAC (128,192,256) - AFT
    * AES-XTS (128,256) - AFT
    * HMAC (SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512)
    * SHA (1, 224, 256, 384, 512) - AFT, MCT
    * SHA3 (224, 256, 384, 512) - AFT, MCT
    * SHAKE (128, 256) - AFT, MCT, VOT
    * TDES-CBC - AFT, MCT
    * TDES-ECB - AFT, MCT
    * RSA
    * ECDSA


Application Information
-----------------------

If a ``.req`` file is used as input, the application generates a response
file (``.rsp``) after completion. The ``.req`` file has missing fields that
the application fills in. For example, when
performing encryption the cipher text is absent; when performing decryption
the plain text is absent. These are computed and added to the ``.rsp`` file
at the end of each operation.

The application can also run with a ``.rsp`` file as input. In this case,
it generates a new ``.rsp`` with an additional verification line. The output
should match the input ``.rsp``, which is useful for validating that the
application performed the operations correctly.

Compiling the Application
-------------------------

* Compile Application

    To compile the sample application see :doc:`compiling`.

*  Run ``dos2unix`` on the request files

    .. code-block:: console

         dos2unix AES/req/*
         dos2unix GCM/req/*
         dos2unix CCM/req/*
         dos2unix CMAC/req/*
         dos2unix HMAC/req/*
         dos2unix TDES/req/*
         dos2unix SHA/req/*

Running the Application
-----------------------

The application requires a number of command line options:

    .. code-block:: console

         ./dpdk-fips_validation [EAL options]
         -- --req-file FILE_PATH/FOLDER_PATH
         --rsp-file FILE_PATH/FOLDER_PATH
         [--cryptodev DEVICE_NAME] [--cryptodev-id ID] [--path-is-folder]
         --mbuf-dataroom DATAROOM_SIZE

where,
  * req-file: The path of the request file or folder, indicated by
    ``path-is-folder`` option.

  * rsp-file: The path where the response file or folder is stored, indicated by
    ``path-is-folder`` option.

  * cryptodev: The name of the target DPDK Crypto device to be validated.

  * cryptodev-id: The id of the target DPDK Crypto device to be validated.

  * path-is-folder: If present, the application treats req-file and rsp-file
    as folder paths.

  * mbuf-dataroom: By default the application creates mbuf pool with maximum
    possible data room (65535 bytes). To test the scatter-gather
    list feature of a PMD, this value may be set to reduce the dataroom
    size so that the input data is divided into multiple chained mbufs.


To run the application in linux environment to test one AES FIPS test data
file for crypto_aesni_mb PMD, issue the command:

.. code-block:: console

    $ ./dpdk-fips_validation --vdev crypto_aesni_mb --
    --req-file /PATH/TO/REQUEST/FILE.req --rsp-file ./PATH/TO/RESPONSE/FILE.rsp
    --cryptodev crypto_aesni_mb

To run the application in linux environment to test all AES-GCM FIPS test
data files in one folder for crypto_aesni_gcm PMD, issue the command:

.. code-block:: console

    $ ./dpdk-fips_validation --vdev crypto_aesni_gcm0 --
    --req-file /PATH/TO/REQUEST/FILE/FOLDER/
    --rsp-file ./PATH/TO/RESPONSE/FILE/FOLDER/
    --cryptodev-id 0 --path-is-folder

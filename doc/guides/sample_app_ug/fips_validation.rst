..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

Federal Information Processing Standards (FIPS) CryptoDev Validation
====================================================================

Overview
--------

Federal Information Processing Standards (FIPS) are publicly announced standards
developed by the United States federal government for use in computer systems by
non-military government agencies and government contractors.

This application is used to parse and perform symmetric cryptography
computation to the NIST Cryptographic Algorithm Validation Program (CAVP) and
Automated Crypto Validation Protocol (ACVP) test vectors.

For an algorithm implementation to be listed on a cryptographic module
validation certificate as an Approved security function, the algorithm
implementation must meet all the requirements of FIPS 140-2 (in the case of CAVP)
and FIPS 140-3 (in the case of ACVP) and must successfully complete the
cryptographic algorithm validation process.

Limitations
-----------

The following sections describe limitations for CAVP and ACVP.

CAVP
~~~~

* The version of request file supported is ``CAVS 21.0``.
* If the header comment in a ``.req`` file does not contain an Algo tag
  (i.e., ``AES,TDES,GCM``), you need to manually add it into the header comment.
  For example::

      # VARIABLE KEY - KAT for CBC / # TDES VARIABLE KEY - KAT for CBC

* The application does not supply the test vectors. The user is expected to
  obtain the test vector files from the `CAVP
  <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers>`_
  website. To obtain the ``.req`` files, you need to
  email a person from the NIST website and pay for the ``.req`` files.
  The ``.rsp`` files from the site can be used to validate and compare with
  the ``.rsp`` files created by the FIPS application.

* Supported test vectors:

    * AES-CBC (128,192,256) - GFSbox, KeySbox, MCT, MMT
    * AES-GCM (128,192,256) - EncryptExtIV, Decrypt
    * AES-CCM (128) - VADT, VNT, VPT, VTT, DVPT
    * AES-CMAC (128) - Generate, Verify
    * HMAC (SHA1, SHA224, SHA256, SHA384, SHA512)
    * TDES-CBC (1 Key, 2 Keys, 3 Keys) - MMT, Monte, Permop, Subkey, Varkey,
      VarText

ACVP
~~~~

* The application does not supply the test vectors. The user is expected to
  obtain the test vector files from the `ACVP <https://pages.nist.gov/ACVP>`_
  website.

* Supported test vectors:

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

If a ``.req`` file is used as the input file, after the application finishes
running it generates a response file (``.rsp``). The differences between
the two files are as follows: the ``.req`` file has missing information (for instance,
if performing encryption, you do not have the cipher text, and that is
generated in the response file); and if performing decryption, it does not
have plain text until the work has finished. In the response file, this information
is added onto the end of each operation.

The application can be run with a ``.rsp`` file as input. The outcome is that
an extra line in the generated ``.rsp`` file is added. This should be the same
as the ``.rsp`` used to run the application. This is useful for validating if
the application has performed the operation correctly.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

Run ``dos2unix`` on the request files:

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

where:

*   req-file: The path of the request file or folder, separated by the
    ``path-is-folder`` option.

*   rsp-file: The path that the response file or folder is stored, separated by the
    ``path-is-folder`` option.

*   cryptodev: The name of the target DPDK Crypto device to be validated.

*   cryptodev-id: The ID of the target DPDK Crypto device to be validated.

*   path-is-folder: If present, the application expects req-file and rsp-file
    to be folder paths.

*   mbuf-dataroom: By default, the application creates an mbuf pool with maximum
    possible data room (65535 bytes). If the user wants to test the scatter-gather
    list feature of the PMD, this value can be set to reduce the dataroom
    size so that the input data may be divided into multiple chained mbufs.


To run the application in a Linux environment to test one AES FIPS test data
file for the crypto_aesni_mb PMD, issue the command:

.. code-block:: console

    $ ./dpdk-fips_validation --vdev crypto_aesni_mb --
    --req-file /PATH/TO/REQUEST/FILE.req --rsp-file ./PATH/TO/RESPONSE/FILE.rsp
    --cryptodev crypto_aesni_mb

To run the application in a Linux environment to test all AES-GCM FIPS test
data files in one folder for the crypto_aesni_gcm PMD, issue the command:

.. code-block:: console

    $ ./dpdk-fips_validation --vdev crypto_aesni_gcm0 --
    --req-file /PATH/TO/REQUEST/FILE/FOLDER/
    --rsp-file ./PATH/TO/RESPONSE/FILE/FOLDER/
    --cryptodev-id 0 --path-is-folder

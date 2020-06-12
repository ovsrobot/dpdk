..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

.. _mp_crypto:

Multi-process Crypto Sample Application
=======================================

The Multi-process Crypto application is a simple application that
allows to run crypto related operations in a multiple process environment. It
builds on the EAL primary/secondary process infrastructure.

The application allows a user to configure devices, setup queue-pairs, create
and init sessions and specify data-path flow (enqueue/dequeue) in different
processes. The app can help to check if the PMD behaves correctly
in scenarios like the following:

* device is configured in primary process, queue-pairs are setup in secondary process

* queue pair is shared across processes, i.e. enqueue in one process and dequeue in another


Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``mp_crypto`` sub-directory.

Running the Application
-----------------------

App binary: mp_crypto (in mp_crypto/build/app)

For running PRIMARY or SECONDARY process standard EAL options apply:

.. code-block:: console

    ./mp_crypto --proc-type primary

    ./mp_crypto --proc-type secondary

.. Note::

	The same set of BDFs must to be passed to all processes.

.. Note::
	The same crypto devices must be created in all processes, e.g. in qat
	case if asym and sym devices are enabled in the primary process, they
	must be enabled in all secondary processes.

General help can by checked by running:

.. code-block:: console

    ./mp_crypto -- -h

The application has a number of command line options:

.. code-block:: console

    ./mp_crypto -- --devtype [dev-name]

This command specifies which driver to use by its name (for example "crypto_qat").
The same name must be passed to all processes.

.. code-block:: console

    ./mp_crypto -- --config_dev [devA, devB,]

This commands specifies the list of devices that should be configured by this process,
this results in a call to the ``rte_cryptodev_configure`` API. devX is a positive
integer (including zero), the value is according to probe order (from smallest
BDF number), not necessarily the cmdline order.

Example command:

.. code-block:: console

    ./mp_crypto -w 03:01.2 -w 03:01.1 -w 03:01.3 --config-dev 0,2

will configure devices 03:01.1 and 03:01.3.

.. code-block:: console

    ./mp_crypto -- --qp-config=[devA]:[qp_A, qp_B,];[devB]:[qp_A, qp_C];

devX - positive integer (including zero), as in config_dev command

qp_X - positive integer (including zero), specifies which queue pair shoud be setup

This command specifies which queue pairs should be setup, resulting in a call to
``rte_cryptodev_queue_pair_setup`` API.

.. code-block:: console

    ./mp_crypto -w 03:01.2 -w 03:01.1 -w 03:01.3 --qp-config="0:0,1;1:1;2:0,1;"

This command will configure queue pairs 0 and 1 on device 0 (03:01.1), queue pair 1
on device 1 (03:01.2), queue pairs 0 and 1 on device 2 (03:01.3). The device in question
should be configured before that, though not necessarily by the same process.

.. code-block:: console

    ./mp_crypto -- --enq=[devX]:[qpX]:[ops]:[vector_id]
    ./mp_crypto -- --deq=[devX]:[qpX]:[ops]:[vector_id]

devX - positive integer (including zero), as in config_dev command

qp_X - positive integer (including zero), as in qp-config command

ops - when positive integer - number of operations to enqueue/dequeue, when 0 infinite loop

vector_id - positive integer (including zero), vector_id used by this process

This commands will enqueue/dequeue "ops" number of packets to qp_X on devX.
Example usage:

.. code-block:: console

    ./mp_crypto -- --enq=2:0:0:0, --deq=2:0:0:0,

Note. ',' comma character is necessary at the end due to some parser shortcomings.

To close application when running in an infinite loop a signal handler is
registered to catch interrupt signals i.e. ``ctrl-c`` should be used. When
used in primary process other processes will be notified about exiting
intention and will close after collecting remaining packets (if dequeuing).

Example commands
----------------

Use different two different devices on 3 separate queues:

.. code-block:: console

    ./mp_crypto --proc-type primary -c 1 -w 03:01.1 -w 03:01.2 -- --devtype "crypto_qat" --config-dev 0,1   --qp-config="0:0,1;1:0,1;" --session-mask=0x3  --enq=0:0:0:0, --deq=0:0:0:0,  --print-stats
    ./mp_crypto --proc-type secondary -c 2 -w 03:01.1 -w 03:01.2 -- --devtype "crypto_qat"  --enq=0:1:0:0, --deq=0:1:0:0,  --print-stats
    ./mp_crypto --proc-type secondary -c 4 -w 03:01.1 -w 03:01.2 -- --devtype "crypto_qat"  --enq=1:0:0:0, --deq=1:0:0:0,  --print-stats

Use different processes to enqueue and dequeue to one queue pair:

.. code-block:: console

    ./mp_crypto --proc-type primary -c 1 -w 03:01.1 -- --devtype "crypto_qat" --config-dev 0    --session-mask=0x3 --qp-config="0:1;"   --enq=0:1:0:0,   --print-stats
    ./mp_crypto --proc-type secondary -c 2 -w 03:01.1 -- --devtype "crypto_qat"  --deq=0:1:0:0,   --print-stats

Limitations
-----------

Only one crypto vector and session type is possible to chose right now and it is AES-GCM test case.

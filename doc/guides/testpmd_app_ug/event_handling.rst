..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 HiSilicon Limited.

Event Handling
==============

The ``testpmd`` application supports following two type event handling:

ethdev events
-------------

The ``testpmd`` provide options "--print-event" and "--mask-event" to control
whether display such as "Port x y event" when received "y" event on port "x".
This is named as default processing.

This section details the support events, unless otherwise specified, only the
default processing is support.

- ``RTE_ETH_EVENT_INTR_LSC``:
  If device started with lsc enabled, the PMD will launch this event when it
  detect link status changes.

- ``RTE_ETH_EVENT_QUEUE_STATE``:
  Used when notify queue state event changed, for example: vhost PMD use this
  event report whether vring enabled.

- ``RTE_ETH_EVENT_INTR_RESET``:
  Used to report reset interrupt happened, this event only reported when the
  PMD supports ``RTE_ETH_ERROR_HANDLE_MODE_PASSIVE``.

- ``RTE_ETH_EVENT_VF_MBOX``:
  Used as a PF to process mailbox messages of the VFs to which the PF belongs.

- ``RTE_ETH_EVENT_INTR_RMV``:
  Used to report device removal event. The ``testpmd`` will remove the port
  later.

- ``RTE_ETH_EVENT_NEW``:
  Used to report port was probed event. The ``testpmd`` will setup the port
  later.

- ``RTE_ETH_EVENT_DESTROY``:
  Used to report port was released event. The ``testpmd`` will changes the
  port's status.

- ``RTE_ETH_EVENT_MACSEC``:
  Used to report MACsec offload related event.

- ``RTE_ETH_EVENT_IPSEC``:
  Used to report IPsec offload related event.

- ``RTE_ETH_EVENT_FLOW_AGED``:
  Used to report new aged-out flows was detected. Only valid with mlx5 PMD.

- ``RTE_ETH_EVENT_RX_AVAIL_THRESH``:
  Used to report available Rx descriptors was smaller than the threshold. Only
  valid with mlx5 PMD.

- ``RTE_ETH_EVENT_ERR_RECOVERING``:
  Used to report error happened, and PMD will do recover after report this
  event. The ``testpmd`` will stop packet forwarding when received the event.

- ``RTE_ETH_EVENT_RECOVERY_SUCCESS``:
  Used to report error recovery success. The ``testpmd`` will restart packet
  forwarding when received the event.

- ``RTE_ETH_EVENT_RECOVERY_FAILED``:
  Used to report error recovery failed. The ``testpmd`` will display one
  message to show which ports failed.

.. note::

   The ``RTE_ETH_EVENT_ERR_RECOVERING``, ``RTE_ETH_EVENT_RECOVERY_SUCCESS`` and
   ``RTE_ETH_EVENT_RECOVERY_FAILED`` only reported when the PMD supports
   ``RTE_ETH_ERROR_HANDLE_MODE_PROACTIVE``.

device events
-------------

Including two events ``RTE_DEV_EVENT_ADD`` and ``RTE_DEV_EVENT_ADD``, and
enabled only when the ``testpmd`` stated with options "--hot-plug".

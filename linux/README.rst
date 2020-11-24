Building Linux Drivers
======================

Prerequisites
-------------

The system must have relevant Linux kernel headers or source code installed.

Build
-----

To build ``igb_uio`` driver, simple run ``make`` command inside the
``igb_uio`` directory:

.. code-block:: console

    cd igb_uio
    make

If compiling against a specific kernel source directory is required, it is
possible to specify the kernel source directory using the ``KSRC`` variable:

.. code-block:: console

    make KSRC=/path/to/custom/kernel/source

Load the driver
---------------

The ``igb_uio`` driver requires the UIO driver to be loaded beforehand (these
commands are to be run as ``root`` user):

.. code-block:: console

    modprobe uio
    insmod igb_uio.ko

Clean the build directory
-------------------------

To clean the build directory, the following command can be run:

.. code-block:: console

    make clean

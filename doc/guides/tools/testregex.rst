.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2020 Mellanox Technologies, Ltd

dpdk-test-regex Tool
====================

The ``dpdk-test-regex`` tool is a Data Plane Development Kit (DPDK)
application that allows functional testing and performance measurement for
the RegEx PMDs.
The test supports only one core and one PMD.
It is based on precomplied rule file, and an input file, both of them can
be selected using command-line options.

In general case, each PMD has it's own rule file.

The test outputs the performance, the results matching (rule id, position, len)
for each job and also a list of matches (rule id, position , len) in absulote
position.


Limitations
~~~~~~~~~~~

* Only one queue is supported.

* Supports only precompiled rules.

EAL Options
~~~~~~~~~~~

The following are the EAL command-line options that can be used in conjunction
with the ``dpdk-test-regex`` application.
See the DPDK Getting Started Guides for more information on these options.


*   ``-w <PCI>``

	Add a PCI device in white list.


Application Options
~~~~~~~~~~~~~~~~~~~

 ``--rules NAME``: precompiled rule file

 ``--data NAME``: data file to use

 ``--nb_jobs N``: number of jobs to use

 ``--perf N``: only outputs the performance data

 ``--nb_iter N``: number of iteration to run

 ``--help``: prints this help


Compiling the Tool
------------------

The ``dpdk-test-regex`` application depends on RegEx lib ``rte_regexdev``.


Generating the data
-------------------

In the current version, the compiled rule file is loaded with a rule that
matches 'hello world'. To create the data file,
it is possible to use the included python script ``generate_data_file.py``
 which generates two files,
``input.txt`` which holds the input buffer. An input buffer is a random number
of spaces chars followed by the phrase 'hello world'.
This sequence is repeated a random number of times.
The second file is ``res.txt`` which holds the position of each
of the 'hello world' in the input file.


Running the Tool
----------------

The tool has a number of command line options. Here is the sample command line:

.. code-block:: console

   ./build/app/testregex -w 83:00.0 -- --rules app/test-regex/hello_world.rof2 --data app/test-regex/input.txt --job 100

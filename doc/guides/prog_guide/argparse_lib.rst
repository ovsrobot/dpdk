.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2024 HiSilicon Limited

Argparse Library
================

The argparse library provides argument parsing functionality and makes it easy to write user-friendly command-line programming.

Features and Capabilities
-------------------------

- Supports parsing of optional arguments (which can contain no-value,
  required-value and optional-values).

- Supports parsing of positional arguments (which must contain required-values).

- Supports automatic generation of usage information.

- Provides issue errors when an argument is invalid

- Supports parsing arguments in two ways:

  #. autosave: used for parsing known value types;
  #. callback: will invoke user callback to parse.

Usage Guide
-----------

The following code demonstrates how to use the following:

.. code-block:: C

   static int
   argparse_user_callback(uint32_t index, const char *value, void *opaque)
   {
      if (index == 1) {
         /* process "--ddd" argument, because it is configured as no-value,
          * the parameter 'value' is NULL.
          */
         ...
      } else if (index == 2) {
         /* process "--eee" argument, because it is configured as
          * required-value, the parameter 'value' must not be NULL.
          */
         ...
      } else if (index == 3) {
         /* process "--fff" argument, because it is configured as
          * optional-value, the parameter 'value' maybe NULL or not NULL,
          * depend on input.
          */
         ...
      } else if (index == 300) {
         /* process "ppp" argument, because it's a positional argument,
          * the parameter 'value' must not be NULL.
          */
         ...
      } else {
         return -EINVAL;
      }
   }

   static int aaa_val, bbb_val, ccc_val, ooo_val;

   static struct rte_argparse obj = {
      .prog_name = "test-demo",
      .usage = "[EAL options] -- [optional parameters] [positional parameters]",
      .descriptor = NULL,
      .epilog = NULL,
      .exit_on_error = true,
      .callback = argparse_user_callback,
      .args = {
         { "--aaa", "-a", "aaa argument", &aaa_val, (void *)100, RTE_ARGPARSE_ARG_NO_VALUE       | RTE_ARGPARSE_ARG_VALUE_INT },
         { "--bbb", "-b", "bbb argument", &bbb_val, NULL,        RTE_ARGPARSE_ARG_REQUIRED_VALUE | RTE_ARGPARSE_ARG_VALUE_INT },
         { "--ccc", "-c", "ccc argument", &ccc_val, (void *)200, RTE_ARGPARSE_ARG_OPTIONAL_VALUE | RTE_ARGPARSE_ARG_VALUE_INT },
         { "--ddd", "-d", "ddd argument", NULL,     (void *)1,   RTE_ARGPARSE_ARG_NO_VALUE       },
         { "--eee", "-e", "eee argument", NULL,     (void *)2,   RTE_ARGPARSE_ARG_REQUIRED_VALUE },
         { "--fff", "-f", "fff argument", NULL,     (void *)3,   RTE_ARGPARSE_ARG_OPTIONAL_VALUE },
         { "ooo",   NULL, "ooo argument", &ooo_val, NULL,        RTE_ARGPARSE_ARG_REQUIRED_VALUE | RTE_ARGPARSE_ARG_VALUE_INT },
         { "ppp",   NULL, "ppp argument", NULL,     (void *)300, RTE_ARGPARSE_ARG_REQUIRED_VALUE },
      },
   };

   int
   main(int argc, char **argv)
   {
      ...
      ret = rte_argparse_parse(&obj, argc, argv);
      ...
   }

In this example, the arguments thhat start with a hyphen (-) are optional
arguments ("--aaa"/"--bbb"/"--ccc"/"--ddd"/"--eee"/"--fff").
The arguments that do not start with a hyphen (-) are positional arguments
("ooo"/"ppp").

Every argument must set whether it carries a value (one of
``RTE_ARGPARSE_ARG_NO_VALUE``, ``RTE_ARGPARSE_ARG_REQUIRED_VALUE`` and
``RTE_ARGPARSE_ARG_OPTIONAL_VALUE``).

.. note::

   Positional argument must set ``RTE_ARGPARSE_ARG_REQUIRED_VALUE``.

User Input Requirements
~~~~~~~~~~~~~~~~~~~~~~~

For optional arguments which have no-value,
the following mode is supported (take above "--aaa" as an example):

- The single mode: "--aaa" or "-a".

For optional arguments which have required-value,
the following two modes are supported (take above "--bbb" as an example):

- The kv mode: "--bbb=1234" or "-b=1234".

- The split mode: "--bbb 1234" or "-b 1234".

For optional arguments which have optional-value,
the following two modes are supported (take above "--ccc" as an example):

- The single mode: "--ccc" or "-c".

- The kv mode: "--ccc=123" or "-c=123".

For positional arguments which must have required-value,
their values are parsing in the order defined.

.. note::

   The compact mode is not supported.
   Take above "-a" and "-d" as an example, don't support "-ad" input.

Parsing the Autosave Method
~~~~~~~~~~~~~~~~~~~~~~~

Arguments of a known value type (e.g. ``RTE_ARGPARSE_ARG_VALUE_INT``)
can be parsed using the autosave method,
The result will save in the ``val_saver`` field.

In the above example, the arguments "--aaa"/"--bbb"/"--ccc" and "ooo"
both use this method. The parsing is as follows:

- For argument "--aaa", it is configured as no-value,
  so the ``aaa_val`` will be set to ``val_set`` field
  which is 100 in the above example.

- For argument "--bbb", it is configured as required-value,
  so the ``bbb_val`` will be set to user input's value
  (e.g. will be set to 1234 with input "--bbb 1234").

- For argument "--ccc", it is configured as optional-value.
  If user only input "--ccc", then the ``ccc_val`` will be set to ``val_set`` field
  which is 200 in the above example;
  If user input "--ccc=123", then the ``ccc_val`` will be set to 123.

- For argument "ooo", it is positional argument,
  the ``ooo_val`` will be set to user input's value.

Parsing by Callback Method
~~~~~~~~~
You may choose to use the callback method to parse.
To do so, define a unique index for the argument
and make the ``val_save`` field to be NULL as a zero value-type.

In the above example, the arguments "--ddd"/"--eee"/"--fff" and "ppp" both use this method.

Multiple Times Argument
~~~~~~~~~~~~~~~~~~~~~~~

If you want to support the ability to enter the same argument multiple times,
then you should mark ``RTE_ARGPARSE_ARG_SUPPORT_MULTI`` in the ``flags`` field.
For example:

.. code-block:: C

   { "--xyz", "-x", "xyz argument", NULL, (void *)10, RTE_ARGPARSE_ARG_REQUIRED_VALUE | RTE_ARGPARSE_ARG_SUPPORT_MULTI },

Then the user input could contain multiple "--xyz" arguments.

.. note::

   The multiple times argument is only supported with optional argument
   and must be parsed by callback way.

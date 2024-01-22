.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2024 HiSilicon Limited

Argparse Library
================

The argparse library provides argument parse functionality, this library makes
it easy to write user-friendly command-line program.

Features and Capabilities
-------------------------

- Support parse optional argument (which could take with no-value,
  required-value and optional-value).

- Support parse positional argument (which must take with required-value).

- Support automatic generate usage information.

- Support issue errors when provide with invalid arguments.

- Support parse argument by two way: 1) autosave: for which known value types,
  this way can be used; 2) callback: will invoke user callback to parse.

Usage Guide
-----------

The following code demonstrates how to initialize:

.. code-block:: C

   static int
   argparse_user_callback(uint32_t index, const char *value, void *opaque)
   {
      if (index == 1) {
         /* process "--ddd" argument, because it has no-value, the parameter value is NULL. */
         ...
      } else if (index == 2) {
         /* process "--eee" argument, because it has required-value, the parameter value must not NULL. */
         ...
      } else if (index == 3) {
         /* process "--fff" argument, because it has optional-value, the parameter value maybe NULL or not NULL, depend on input. */
         ...
      } else if (index == 300) {
         /* process "ppp" argument, because it's a positional argument, the parameter value must not NULL. */
         ...
      } else {
         return -EINVAL;
      }
   }

   int aaa_val, bbb_val, ccc_val, ooo_val;

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

Parsing by autosave way
~~~~~~~~~~~~~~~~~~~~~~~

For which known value types (just like ``RTE_ARGPARSE_ARG_VALUE_INT``"), could
parse by autosave way, just like above "--aaa"/"--bbb"/"--ccc" optional
arguments:

If the user input parameter are: "program --aaa --bbb 1234 --ccc=20 ...", then
the aaa_val will equal 100, the bbb_val will equal 1234 and the ccc_val will
equal 20.

If the user input parameter are: "program --ccc ...", then the aaa_val and
bbb_val will not modify, and ccc_val will equal 200.

Parsing by callback way
~~~~~~~~~~~~~~~~~~~~~~~

It could also choose to use callback to parse, just define a unique index for
the argument and make the field val_save to be NULL also zero value-type. Just
like above "--ddd"/"--eee"/"--fff" optional arguments:

If the user input parameter are: "program --ddd --eee 2345 --fff=30 ...", the
function argparse_user_callback() will be invoke to parse the value.

Positional arguments
~~~~~~~~~~~~~~~~~~~~

The positional arguments could not start with a hyphen (-). The above code show
that there are two positional arguments "ooo"/"ppp", it must be flags with
``RTE_ARGPARSE_ARG_REQUIRED_VALUE``, and it also could use autosave or callback
to parsing:

If the user input parameter are: "program [optionals] 456 789", then the ooo_val
will equal 456, and ppp_val will equal 789.

Multiple times argument
~~~~~~~~~~~~~~~~~~~~~~~

If want to support the ability to enter the same argument multiple times, then
should mark ``RTE_ARGPARSE_ARG_SUPPORT_MULTI`` in flags field. For examples:

.. code-block:: C

   ...
   { "--xyz", "-x", "xyz argument", NULL, (void *)10, RTE_ARGPARSE_ARG_REQUIRED_VALUE | RTE_ARGPARSE_ARG_SUPPORT_MULTI },
   ...

Then the user input parameter could be: "program --xyz 123 --xyz 456 ...".

It's important to note that the multiple times flag only support with optional
argument and must be parsing by callback way.

Other Notes
~~~~~~~~~~~

For optional arguments, short-name can be defined or not defined. For arguments
that have required value, the following inputs are supported:
"program --bbb=123 --eee 456 ..." or "program -b=123 -e 456 ...".

For arguments that have optional value, the following inputs are supported:
"program --ccc --fff=100 ..." or "program -c -f=100".

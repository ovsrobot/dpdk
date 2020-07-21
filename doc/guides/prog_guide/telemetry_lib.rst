..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

Telemetry Library
=================

The Telemetry library provides an interface to retrieve information from a
variety of DPDK libraries. The library provides this information via socket
connection, taking requests from a connected client and replying with the JSON
response containing the requested telemetry information.

Telemetry is enabled to run by default when running a DPDK application, and the
telemetry information from enabled libraries is made available. Libraries are
responsible for registering their own commands, and providing the callback
function that will format the library specific stats into the correct data
format, when requested.


Creating Callback Functions
---------------------------


Function Type
~~~~~~~~~~~~~

When creating a callback function in a library/app, it must be of the following type:

.. code-block:: c

    typedef int (*telemetry_cb)(const char *cmd, const char *params,
            struct rte_tel_data *info);

For example, the callback for "/ethdev/list" is:

.. code-block:: c

    static int
    handle_port_list(const char *cmd __rte_unused, const char *params __rte_unused,
            struct rte_tel_data *d)

The parameters for a callback function are:

* **cmd**

  This is the command requested by the client, e.g. "/ethdev/list".
  For most callbacks this may be unused, however it will allow for handling
  multiple commands in one callback function. This can be seen in the example
  callback below.

* **params**

  This will contain any parameters required for the command. For example
  when calling "/ethdev/link_status,0", the port ID will be passed to the
  callback function in params. This can be seen in the example callback below.

* **d**

  The rte_tel_data pointer will be used by the callback function to format the
  requested data to be returned to Telemetry. The data APIs provided will
  enable adding to the struct, examples of this are shown later in this
  document.

**Example Callback**

This callback is an example of handling multiple commands in one callback,
and also shows the use of params which holds a port ID. The params input needs
to be validated and converted to the required integer type for port ID. The cmd
parameter is then used in a comparison to decide which command was requested,
which will decide what port information should fill the rte_tel_data structure.

.. code-block:: c

   int
   handle_cmd_request(const char *cmd, const char *params,
         struct rte_tel_data *d)
   {
      int port_id, used = 0;

      if (params == NULL || strlen(params) == 0 || !isdigit(*params))
         return -1;

      port_id = atoi(params);
      if (!rte_eth_dev_is_valid_port(port_id))
         return -1;

      if (strcmp(cmd, "/cmd_1") == 0)
         /* Build up port data requested for command 1 */
      else
         /* Build up port data requested for command 2 */

       return used;
   }


Formatting Data
~~~~~~~~~~~~~~~

The callback function provided by the library must format its telemetry
information in the required data format. The Telemetry library provides a data
utilities API to build up the data structure with the required information.
The telemetry library is then responsible for formatting the data structure
into a JSON response before sending to the client.

* **Array Data**

  Some data will need to be formatted in a list structure. For example, the
  ethdev library provides a list of available ethdev ports in a formatted data
  response, constructed using the following functions to build up the list:

  .. code-block:: c

      rte_tel_data_start_array(d, RTE_TEL_INT_VAL);
          RTE_ETH_FOREACH_DEV(port_id)
              rte_tel_data_add_array_int(d, port_id);

  The resulting response to the client shows the port list data provided above
  by the handler function in ethdev, placed in a JSON reply by telemetry:

  .. code-block:: console

     {"/ethdev/list": [0, 1]}

* **Dictionary Data**

  For data that needs to be structured in a dictionary with key/value pairs,
  the data utilities API can also be used. For example, telemetry provides an
  info command that has multiple key/value pairs, constructed in the callback
  function shown below:

  .. code-block:: c

     rte_tel_data_start_dict(d);
     rte_tel_data_add_dict_string(d, "version", rte_version());
     rte_tel_data_add_dict_int(d, "pid", getpid());
     rte_tel_data_add_dict_int(d, "max_output_len", MAX_OUTPUT_LEN);

  The resulting response to the client shows the key/value data provided above
  by the handler function in telemetry, placed in a JSON reply by telemetry:

  .. code-block:: console

     {"/info": {"version": "DPDK 20.08.0-rc0", "pid": 3838, "max_output_len": 16384}}

* **String Data**

  Telemetry also supports single string data. The data utilities API can again
  be used for this, see the example below.

  .. code-block:: c

     rte_tel_data_string(d, "This is an example string");

  Giving the following response to the client:

  .. code-block:: console

     {"/string_example": "This is an example string"}

For more information on the range of data functions available in the API,
please refer to the docs.


Registering Commands
--------------------

Libraries and applications must register commands to make their information
available via the Telemetry library. This involves providing a string command
in the required format ("/library/command"), the callback function that
will handle formatting the information when required, and help text for the
command. An example showing ethdev commands being registered is shown below:

.. code-block:: c

    rte_telemetry_register_cmd("/ethdev/list", handle_port_list,
            "Returns list of available ethdev ports. Takes no parameters");
    rte_telemetry_register_cmd("/ethdev/xstats", handle_port_xstats,
            "Returns the extended stats for a port. Parameters: int port_id");
    rte_telemetry_register_cmd("/ethdev/link_status", handle_port_link_status,
            "Returns the link status for a port. Parameters: int port_id");


Using Commands
--------------

To use commands, with a DPDK app running (e.g. testpmd), use the
dpdk-telemetry.py script. For details on its use, see the :ref:`telemetry`.

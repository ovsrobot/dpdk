"""
User-defined exceptions used across the framework.
"""


class TimeoutException(Exception):

    """
    Command execution timeout.
    """

    def __init__(self, command, output):
        self.command = command
        self.output = output

    def __str__(self):
        msg = "TIMEOUT on %s" % (self.command)
        return msg

    def get_output(self):
        return self.output


class SSHConnectionException(Exception):

    """
    SSH connection error.
    """

    def __init__(self, host):
        self.host = host

    def __str__(self):
        return "Error trying to connect with %s" % self.host


class SSHSessionDeadException(Exception):

    """
    SSH session is not alive.
    It can no longer be used.
    """

    def __init__(self, host):
        self.host = host

    def __str__(self):
        return "SSH session with %s has been dead" % self.host


class ConfigParseException(Exception):

    """
    Configuration file parse failure exception.
    """

    def __init__(self, conf_file):
        self.config = conf_file

    def __str__(self):
        return "Failed to parse config file [%s]" % (self.config)

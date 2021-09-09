#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation
# pylint: disable=invalid-name
'''Tool to notify maintainers of expired symbols'''
import os
import smtplib
import ssl
import sys
import subprocess
import argparse
from argparse import RawTextHelpFormatter
import time
from email.message import EmailMessage
from pathlib import Path

DESCRIPTION = '''
Use this script with the output of the DPDK symbol tool, to notify maintainers
and contributors of expired symbols by email. You need to define the environment
variable DPDK_GETMAINTAINER_PATH for this tool to work.

Use terminal output to review the emails before sending.
e.g.
$ devtools/symbol-tool.py list-expired --format-output csv \\
| DPDK_GETMAINTAINER_PATH=<somewhere>/get_maintainer.pl \\
{s} --format-output terminal

Then use email output to send the emails to the maintainers.
e.g.
$ devtools/symbol-tool.py list-expired --format-output csv \\
| DPDK_GETMAINTAINER_PATH=<somewhere>/get_maintainer.pl \\
{s} --format-output email \\
--smtp-server <server> --sender <someone@somewhere.com> --password <password> \\
--cc <someone@somewhere.com>
'''  # noqa: E501

EMAIL_TEMPLATE = '''Hi there,

Please note the symbols listed below have expired. In line with the DPDK ABI
policy, they should be scheduled for removal, in the next DPDK release.

For more information, please see the DPDK ABI Policy, section 3.5.3.
https://doc.dpdk.org/guides/contributing/abi_policy.html

Thanks,

The DPDK Symbol Bot

'''  # noqa: E501

ABI_POLICY = 'doc/guides/contributing/abi_policy.rst'
DPDK_GMP_ENV_VAR = 'DPDK_GETMAINTAINER_PATH'
MAINTAINERS = 'MAINTAINERS'
get_maintainer = ['devtools/get-maintainer.sh',
                  '--email', '-f']


class EnvironException(Exception):
    '''Subclass exception for Pylint\'s happiness.'''


def _die_on_exception(e):
    '''Print an exception, and quit'''

    print('Fatal Error: ' + str(e))
    sys.exit()


def _check_get_maintainers_env():
    '''Check get maintainers scripts are setup'''

    if not Path(get_maintainer[0]).is_file():
        raise EnvironException('Cannot locate DPDK\'s get maintainers script, '
                               ' usually at $' + get_maintainer[0] + '.')

    if DPDK_GMP_ENV_VAR not in os.environ:
        raise EnvironException(DPDK_GMP_ENV_VAR + ' is not defined.')

    if not Path(os.environ[DPDK_GMP_ENV_VAR]).is_file():
        raise EnvironException('Cannot locate get maintainers script, usually'
                               ' at ' + DPDK_GMP_ENV_VAR + '.')


def _get_maintainers(libpath):
    '''Get the maintainers for given library'''

    try:
        _check_get_maintainers_env()
    except EnvironException as e:
        _die_on_exception(e)

    try:
        cmd = get_maintainer + [libpath]
        result = subprocess.run(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=True)
    except subprocess.CalledProcessError as e:
        _die_on_exception(e)

    if result is None:
        return None

    email = result.stdout.decode('utf-8')
    if email == '':
        return None

    email = list(filter(None, email.split('\n')))
    return email


default_maintainers = _get_maintainers(ABI_POLICY) + \
    _get_maintainers(MAINTAINERS)


def get_maintainers(libpath):
    '''Get the maintainers for given library'''
    maintainers = _get_maintainers(libpath)

    if maintainers is None:
        maintainers = default_maintainers

    return maintainers


def get_message(library, symbols, config):
    '''Build email message from symbols, config and maintainers'''
    contributors = {}
    message = {}
    maintainers = get_maintainers(library)

    if maintainers != default_maintainers:
        message['CC'] = default_maintainers.copy()

    if 'CC' in config:
        message.setdefault('CC', []).append(config['CC'])

    message['Subject'] = 'Expired symbols in {}\n'.format(library)

    body = EMAIL_TEMPLATE
    body += '{:<50}{:<25}{:<25}\n'.format('Symbol', 'Contributor', 'Email')
    for sym in symbols:
        body += ('{:<50}{:<25}{:<25}\n'.format(sym,
                                               symbols[sym]['name'],
                                               symbols[sym]['email']))
        email = symbols[sym]['email']
        contributors[email] = ''

    contributors = list(contributors.keys())

    message['To'] = maintainers + contributors
    message['Body'] = body

    return message


class OutputEmail():
    '''Format the output for email'''

    def __init__(self, config):
        self.config = config

        self.terminal = OutputTerminal(config)
        context = ssl.create_default_context()

        # Try to log in to server and send email
        try:
            self.server = smtplib.SMTP(config['smtp_server'], 587)
            self.server.starttls(context=context)  # Secure the connection
            self.server.login(config['sender'], config['password'])
        except EnvironException as e:
            _die_on_exception(e)

    def message(self, message):
        '''send email'''
        self.terminal.message(message)

        msg = EmailMessage()
        msg.set_content(message.pop('Body'))

        for key in message.keys():
            msg[key] = message[key]

        msg['From'] = self.config['sender']
        msg['Reply-To'] = 'no-reply@dpdk.org'

        self.server.send_message(msg)

        time.sleep(1)

    def __del__(self):
        self.server.quit()


class OutputTerminal():  # pylint: disable=too-few-public-methods
    '''Format the output for the terminal'''

    def __init__(self, config):
        self.config = config

    def message(self, message):
        '''Print email to terminal'''

        terminal = 'To:' + ', '.join(message['To']) + '\n'
        if 'sender' in self.config.keys():
            terminal += 'From:' + self.config['sender'] + '\n'

        terminal += 'Reply-To:' + 'no-reply@dpdk.org' + '\n'

        if 'CC' in message:
            terminal += 'CC:' + ', '.join(message['CC']) + '\n'

        terminal += 'Subject:' + message['Subject'] + '\n'
        terminal += 'Body:' + message['Body'] + '\n'

        print(terminal)
        print('-' * 80)


def parse_config(args):
    '''put the command line args in the right places'''
    config = {}
    error_msg = None

    outputs = {
        None: OutputTerminal,
        'terminal': OutputTerminal,
        'email': OutputEmail
    }

    if args.format_output == 'email':
        if args.smtp_server is None:
            error_msg = 'SMTP server'
        else:
            config['smtp_server'] = args.smtp_server

        if args.sender is None:
            error_msg = 'sender'
        else:
            config['sender'] = args.sender

        if args.password is None:
            error_msg = 'password'
        else:
            config['password'] = args.password

    if args.cc is not None:
        config['CC'] = args.cc

    if error_msg is not None:
        print('Please specify a {} for email output'.format(error_msg))
        return None

    config['output'] = outputs[args.format_output]
    return config


def main():
    '''Main entry point'''
    parser = \
        argparse.ArgumentParser(description=DESCRIPTION.format(s=__file__),
                                formatter_class=RawTextHelpFormatter)
    parser.add_argument('--format-output',
                        choices=['terminal', 'email'],
                        default='terminal')
    parser.add_argument('--smtp-server')
    parser.add_argument('--password')
    parser.add_argument('--sender')
    parser.add_argument('--cc')

    args = parser.parse_args()
    config = parse_config(args)
    if config is None:
        return

    symbols = {}
    lastlib = library = ''

    output = config['output'](config)

    for line in sys.stdin:
        line = line.rstrip('\n')

        if line.find('mapfile') >= 0:
            continue
        library, symbol, name, email = line.split(',')

        if library != lastlib:
            message = get_message(lastlib, symbols, config)
            output.message(message)
            symbols = {}

        lastlib = library
        symbols[symbol] = {'name': name, 'email': email}

    # print the last library
    message = get_message(lastlib, symbols, config)
    output.message(message)


if __name__ == '__main__':
    main()

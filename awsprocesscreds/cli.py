from __future__ import print_function
import argparse
import json
import getpass
import sys
import logging
import base64
import xml.dom.minidom

import botocore.session

from .saml import SAMLCredentialFetcher
from .cache import JSONFileCache


import contextlib
import io
import os
import sys
import warnings


def unix_getpass(prompt='Password: ', stream=None):
    """Prompt for a password, with echo turned off.
    Args:
      prompt: Written on stream to ask for the input.  Default: 'Password: '
      stream: A writable file object to display the prompt.  Defaults to
              the tty.  If no tty is available defaults to sys.stderr.
    Returns:
      The seKr3t input.
    Raises:
      EOFError: If our input tty or stdin was closed.
      GetPassWarning: When we were unable to turn echo off on the input.
    Always restores terminal settings before returning.
    """
    passwd = None
    with contextlib.ExitStack() as stack:
        try:
            # Always try reading and writing directly on the tty first.
            fd = os.open('/dev/tty', os.O_RDWR|os.O_NOCTTY)
            tty = io.FileIO(fd, 'w+')
            stack.enter_context(tty)
            input = io.TextIOWrapper(tty)
            stack.enter_context(input)
            if not stream:
                stream = input
        except OSError as e:
            # If that fails, see if stdin can be controlled.
            stack.close()
            try:
                fd = sys.stdin.fileno()
            except (AttributeError, ValueError):
                fd = None
                passwd = fallback_getpass(prompt, stream)
            input = sys.stdin
            if not stream:
                stream = sys.stderr

        if fd is not None:
            try:
                old = termios.tcgetattr(fd)     # a copy to save
                new = old[:]
                new[3] &= ~termios.ECHO  # 3 == 'lflags'
                tcsetattr_flags = termios.TCSAFLUSH
                if hasattr(termios, 'TCSASOFT'):
                    tcsetattr_flags |= termios.TCSASOFT
                try:
                    termios.tcsetattr(fd, tcsetattr_flags, new)
                    passwd = raw_input(prompt, stream, input=input)
                finally:
                    termios.tcsetattr(fd, tcsetattr_flags, old)
                    stream.flush()  # issue7208
            except termios.error:
                if passwd is not None:
                    # _raw_input succeeded.  The final tcsetattr failed.  Reraise
                    # instead of leaving the terminal in an unknown state.
                    raise
                # We can't control the tty or stdin.  Give up and use normal IO.
                # fallback_getpass() raises an appropriate warning.
                if stream is not input:
                    # clean up unused file objects before blocking
                    stack.close()
                passwd = fallback_getpass(prompt, stream)

        stream.write('\n')
        return passwd



def saml(argv=None, prompter=getpass.getpass, client_creator=None,
         cache_dir=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-e', '--endpoint', required=True, help=(
            'The SAML idp endpoint.'
        )
    )
    parser.add_argument(
        '-u', '--username', required=True,
        help='Your SAML username.'
    )
    parser.add_argument(
        '-p', '--provider', required=True, choices=['okta', 'adfs'],
        help=(
            'The name of your SAML provider. Currently okta and adfs '
            'form-based auth is supported.'
        )
    )
    # parser.add_argument(
    #     '-a', '--role-arn', required=True, help=(
    #         'The role arn you wish to assume. Your SAML provider must be '
    #         'configured to give you access to this arn.'
    #     )
    # )

    parser.add_argument(
        '-a', '--role-arn', required=False, help=(
            'The role arn you wish to assume. Your SAML provider must be '
            'configured to give you access to this arn.'
        )
    )

    parser.add_argument(
        '--no-cache', action='store_false', default=True, dest='cache',
        help=(
            'Disables the storing and retrieving of credentials from the '
            'local file cache.'
        )
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', help=('Enables verbose mode.')
    )
    args = parser.parse_args(argv)

    if args.verbose:
        logger = logging.getLogger('awsprocesscreds')
        logger.setLevel(logging.INFO)
        handler = PrettyPrinterLogHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if client_creator is None:
        client_creator = botocore.session.Session().create_client

    cache = {}
    if args.cache:
        cache = JSONFileCache(cache_dir)

    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        provider_name=args.provider,
        saml_config={
            'saml_endpoint': args.endpoint,
            'saml_authentication_type': 'form',
            'saml_username': args.username,
            'role_arn': args.role_arn
        },
        password_prompter=prompter,
        cache=cache
    )
    creds = fetcher.fetch_credentials()
    creds['Version'] = 1
    print(json.dumps(creds) + '\n')


class PrettyPrinterLogHandler(logging.StreamHandler):
    def emit(self, record):
        self._pformat_record_args(record)
        super(PrettyPrinterLogHandler, self).emit(record)

    def _pformat_record_args(self, record):
        if isinstance(record.args, dict):
            record.args = self._pformat_dict(record.args)
        elif getattr(record, 'is_saml_assertion', False):
            formatted = self._pformat_saml_assertion(record.args[0])
            record.args = tuple([formatted])

    def _pformat_dict(self, args):
        return json.dumps(args, indent=4, sort_keys=True)

    def _pformat_saml_assertion(self, assertion):
        xml_string = base64.b64decode(assertion).decode('utf-8')
        return xml.dom.minidom.parseString(xml_string).toprettyxml()

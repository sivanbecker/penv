#!/usr/bin/env python

import click
import logbook
import sys

_logger = logbook.Logger(__name__)
logbook.set_datetime_format('local')

@click.group()
@click.pass_context
def cli(ctx):
    pass

@cli.group()
def tmux():
    pass

@cli.group()
def dhcpawn():
    pass

from ..ldap import dhcpldap as ldap_group
cli.add_command(ldap_group)

from ..ldap import dhcpawn as dhcpawn_group
cli.add_command(dhcpawn_group)

def main_entry_point():
    _log_handler = logbook.StderrHandler()
    with _log_handler.applicationbound():
        return cli(obj={})

if __name__ == '__main__':
    sys.exit(main_entry_point())

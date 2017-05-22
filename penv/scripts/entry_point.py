#!/usr/local/bin/python3

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
def yml():
    pass

from ..ldap import dhcpldap as ldap_group
cli.add_command(ldap_group)

from ..ldap import yml as yml_group
cli.add_command(yml_group)

def main_entry_point():
    _log_handler = logbook.StderrHandler()
    with _log_handler.applicationbound():
        return cli(obj={})

if __name__ == '__main__':
    sys.exit(main_entry_point())

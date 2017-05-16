#!/usr/local/bin/python3

import click

@click.group()
def ldap():
    pass

@ldap.command()
@click.option('--elem', default='raw', help='host/system/ip/mac')
@click.option('--lab/-l', help='Infi1 / telad / gdc /')
def ldap_search(elem, lab):
    click.echo('Connecting LDAP for lab %s' % lab)

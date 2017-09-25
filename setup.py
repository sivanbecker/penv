#!/usr/local/bin/python3

from setuptools import setup

setup(
    name='penv',
    version = '0.0.6',
    author = 'Sivan Becker',
    author_email = 'sivanbecker@gmail.com',
    description = ("dhcp/ldap stuff, dhcpawn populate"),
    license = "BSD",
    keywords = "dhcp ldap",
    py_modules=['penv'],
    install_requires=[
        'Click',
        'pyldap',
        'pyyaml',
        'requests',
        'logbook',
        ],
    entry_points='''
       [console_scripts]
       p=penv.scripts.entry_point:cli
    ''',
)

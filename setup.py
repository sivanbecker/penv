#!/usr/local/bin/python3

from setuptools import setup

setup(
    name='penv',
    version = '0.0.5',
    author = 'Sivan Becker',
    author_email = 'sivanbecker@gmail.com',
    description = ("dhcp, ldap stuff"),
    license = "BSD",
    keywords = "dhcp ldap",
    pymodules=['penv'],
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

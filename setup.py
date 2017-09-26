#!/usr/bin/env python

from setuptools import setup

setup(
    name='penv',
    version = '0.0.7',
    author = 'Sivan Becker',
    author_email = 'sivanbecker@gmail.com',
    description = ("dhcp/ldap stuff, dhcpawn populate"),
    license = "BSD",
    keywords = "dhcp ldap",
    packages=['penv'],
    install_requires=[
        'Click',
        'pyldap',
        'pyyaml',
        'requests',
        'logbook',
        ],
    entry_points = {
        'console_scripts': ['p=penv.scripts.entry_point:cli']
        }
    # entry_points='''
       # [console_scripts]
       # p=penv.scripts.entry_point:cli
    # ''',
)

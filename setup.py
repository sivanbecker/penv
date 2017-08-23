#!/usr/local/bin/python3

from setuptools import setup

setup(
    name='penv',
    version='0.0.4',
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

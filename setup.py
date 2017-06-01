#!/usr/local/bin/python3

from setuptools import setup

setup(
    name='penv',
    version='0.0.3',
    pymodules=['penv'],
    install_requires=[
        'Click',
        'pyldap',
        'pyyaml',
        ],
    entry_points='''
       [console_scripts]
       p=penv.scripts.entry_point:cli
    ''',
)

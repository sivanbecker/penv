#!/usr/local/bin/python3

from setuptools import setup

setup(
    name='penv',
    version='0.0.1',
    pymodules=['penv'],
    install_requires=[
        'Click',
        ],
    entry_points='''
       [console_scripts]
       penv=penv.scripts.entry_point:cli
    ''',
)

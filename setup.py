#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='aw-server',
      version='0.1',
      description='ActivityWatch server',
      author='Erik Bjäreholt',
      author_email='erik@bjareho.lt',
      url='https://github.com/ActivityWatch/aw-server',
      namespace_packages=['aw'],
      packages=['aw.server'],
      install_requires=['aw-core', 'Flask', 'Flask-RESTful', 'Flask-Cors', 'pymongo'],
      entry_points={
            'console_scripts': ['aw-server = aw.server:main']
        }
     )
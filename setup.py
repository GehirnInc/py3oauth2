# -*- coding: utf-8 -*-

import os

from setuptools import setup, find_packages

here = os.path.dirname(__file__)
requires = []
tests_require = [
    'nose',
    'coverage'
]

try:
    import enum
except ImportError:
    requires.append('enum34')


def _read(name):
    try:
        return open(os.path.join(here, name)).read()
    except:
        return ""
readme = _read("README.md")
license = _read("LICENSE.md")

setup(
    name='py3oauth2',
    version='0.1.1',
    test_suite='py3oauth2',
    author='Kohei YOSHIDA',
    author_email='kohei.yoshida@gehirn.co.jp',
    description='OAuth 2.0 library for Python 3.',
    long_description=readme,
    license=license,
    url='https://github.com/GehirnInc/py3oauth2',
    packages=find_packages(),
    install_requires=requires,
    tests_require=tests_require,
)

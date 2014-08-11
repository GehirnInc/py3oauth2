# -*- coding: utf-8 -*-

import os

from setuptools import setup

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
else:
    del enum

try:
    from unittest import mock
except ImportError:
    tests_require.append('mock')
else:
    del mock


def _read(name):
    try:
        return open(os.path.join(here, name)).read()
    except:
        return ""
readme = _read("README.rst")
license = _read("LICENSE.rst")

setup(
    name='py3oauth2',
    version='0.4.5',
    test_suite='py3oauth2',
    author='Kohei YOSHIDA',
    author_email='kohei.yoshida@gehirn.co.jp',
    description='OAuth 2.0 library for Python 3.',
    long_description=readme,
    license=license,
    url='https://github.com/GehirnInc/py3oauth2',
    packages=['py3oauth2'],
    install_requires=requires,
    tests_require=tests_require,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)

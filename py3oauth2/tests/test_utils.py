# -*- coding: utf-8 -*-

from nose.tools import (
    eq_,
    raises,
)
from py3oauth2.utils import (
    normalize_netloc,
    normalize_path,
    normalize_query,
    normalize_url,
)


def test_normalize_url():
    eq_(normalize_url('http://a/b/c/%7Bfoo%7D'),
        normalize_url('hTTP://a/./b/../b/%63/%7bfoo%7d'))


@raises(ValueError)
def test_normalize_url_unknown_scheme():
    normalize_url('example://example.com/')


@raises(ValueError)
def test_normalize_url_fragment():
    normalize_url('http://example.com/#foo')


@raises(ValueError)
def test_normalize_url_invalid_port():
    normalize_url('https://example.com:1bb/#foo')


def test_normalize_netloc():
    eq_(normalize_netloc('eXamPLe.com', 80), 'example.com')
    eq_(normalize_netloc('user:pass@example.com', 80), 'user:pass@example.com')
    eq_(normalize_netloc('user:@example.com', 80), 'user@example.com')
    eq_(normalize_netloc(':pass@example.com', 80), ':pass@example.com')
    eq_(normalize_netloc('example.com:443', 80), 'example.com:443')
    eq_(normalize_netloc('example.com:80', 80), 'example.com')
    eq_(normalize_netloc('example.com:', 80), 'example.com')


def test_normalize_query():
    eq_(normalize_query(''), '')
    eq_(normalize_query('b=c&a=b'), 'a=b&b=c')
    eq_(normalize_query('b&a=b'), 'a=b')
    eq_(normalize_query('b=&a=b'), 'a=b')
    eq_(normalize_query('b=%e3%81%84&a=%e3%81%82'), 'a=%E3%81%82&b=%E3%81%84')


def test_normalize_path():
    eq_(normalize_path(''), '/')
    eq_(normalize_path('//'), '/')
    eq_(normalize_path('/a//b'), '/a/b/')
    eq_(normalize_path('/a/./b'), '/a/b/')
    eq_(normalize_path('/a/foo/../b'), '/a/b/')
    eq_(normalize_path('/%e3%81%82%a%e3%81%84'), '/%E3%81%82%a%E3%81%84/')
    eq_(normalize_path('/%e3%81%82a%e3%81%84'), '/%E3%81%82a%E3%81%84/')

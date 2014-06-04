# -*- coding: utf-8 -*-

import unittest


class TestRequestErrorMeta(unittest.TestCase):

    @property
    def target_class(self):
        from py3oauth2.errors import RequestErrorMeta
        return RequestErrorMeta

    def test_it(self):
        from py3oauth2.message import Parameter
        from py3oauth2.errors import RequestError

        self.target_class('cls', object, {})

        with self.assertRaises(AttributeError):
            self.target_class('cls', (RequestError, ), {})

        with self.assertRaises(AttributeError):
            self.target_class('cls', (RequestError, ), {
                'kind': 'value',
            })

        self.target_class('cls', (RequestError, ), {
            'kind': Parameter(str),
        })

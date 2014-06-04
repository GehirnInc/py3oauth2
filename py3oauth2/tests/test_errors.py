# -*- coding: utf-8 -*-

import unittest

from py3oauth2.tests import mock


class ErrorResponseTest(unittest.TestCase):

    @property
    def target(self):
        from py3oauth2.errors import ErrorResponse
        return ErrorResponse

    def make_target(self, request, is_redirect):
        return self.target(request, is_redirect)

    def test_constructor(self):
        request = object()
        is_redirect = object()

        inst = self.make_target(request, is_redirect)
        self.assertIs(inst.redirect, is_redirect)

    def test_is_redirect(self):
        is_redirect = object()

        inst = self.make_target(object(), is_redirect)
        self.assertIs(inst.is_redirect(), is_redirect)

    def test_get_content_type(self):
        inst = self.make_target(object(), object())
        self.assertEqual(inst.get_content_type(), 'text/json;charset=utf8')

    def test_get_response_body(self):
        inst = self.target.from_dict(object(), object(), {
            'error': 'dummy_error',
        })
        self.assertEqual(inst.get_response_body(), inst.to_json())


class ErrorExceptionTest(unittest.TestCase):

    @property
    def target(self):
        from py3oauth2.errors import ErrorException
        return ErrorException

    def test_constructor(self):
        request = object()
        is_redirect = object()

        inst = self.target(request, is_redirect)
        self.assertIs(inst.request, request)
        self.assertIs(inst.is_redirect, is_redirect)

    def test_response_parse_fail(self):
        from py3oauth2.message import Request

        request = Request()
        request.state = object()

        inst = self.target(request)
        inst.klass = mock.Mock()

        response = inst.response
        inst.klass.from_dict.assert_called_once_with(
            request,
            inst.is_redirect,
            {
                'state': request.state,
            })
        self.assertIs(response, inst.klass.from_dict.return_value)

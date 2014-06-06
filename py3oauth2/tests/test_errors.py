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

    def test_get_content_type(self):
        inst = self.make_target(object(), object())
        self.assertEqual(inst.get_content_type(), 'text/json;charset=utf8')

    def test_get_response_body(self):
        inst = self.target(object())
        inst.update({
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
        redirect_uri = object()

        inst = self.target(request, redirect_uri)
        self.assertIs(inst.request, request)
        self.assertIs(inst.redirect_uri, redirect_uri)

    def test_response_parse_fail(self):
        from py3oauth2.message import Request

        request = Request()
        request.state = object()
        redirect_uri = object()

        inst = self.target(request, redirect_uri)
        inst.klass = mock.Mock()

        response = inst.response
        inst.klass.assert_called_once_with(request, redirect_uri)
        inst.klass.return_value.update.assert_called_once_with({
            'state': request.state,
        })
        self.assertIs(response, inst.klass.return_value)

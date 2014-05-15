# -*- coding: utf-8 -*-

import contextlib
try:
    from unittest import mock
except ImportError:
    import mock

from . import TestBase


class TestRequest(TestBase):

    @property
    def target(self):
        from ..implicitgrant import Request
        return Request

    def test_answer_unauthorized_client_unregistered(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        req = self.target.from_dict({
            'response_type': 'token',
            'client_id': 'unknown_client_id',
        })
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.assertRaises(UnauthorizedClient))
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=True))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        client = self.make_client()
        req = self.target.from_dict({
            'response_type': 'token',
            'client_id': client.id,
        })
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=False))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client_redirect_uri_notmatched(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        client = self.make_client('https://example.com/cb')
        provider = AuthorizationProvider(self.store)
        req = self.target.from_dict({
            'response_type': 'token',
            'client_id': client.id,
            'redirect_uri': 'https://example.com/dummycb',
        })
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=True))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer(self):
        from ..provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        client = self.make_client()

        req = self.target.from_dict({
            'response_type': 'token',
            'client_id': client.id,
            'state': 'statestring',
        })
        with mock.patch.object(provider, 'authorize_client',
                               return_value=True):
            resp = req.answer(provider, self.owner)

        resp.validate()

        self.assertIsInstance(resp, req.response)
        token = self.store.get_access_token(resp.access_token)
        self.assertIsNotNone(token)
        self.assertEqual(len(token.get_token()), 40)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(resp.scope, token.get_scope())
        self.assertEqual(resp.state, req.state)
        self.assertTrue(resp.is_redirect())

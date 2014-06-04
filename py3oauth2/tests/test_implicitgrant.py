# -*- coding: utf-8 -*-

import contextlib

from py3oauth2.tests import (
    TestBase,
    mock,
)


class TestRequest(TestBase):

    @property
    def target(self):
        from py3oauth2.implicitgrant import Request
        return Request

    def test_answer_unauthorized_client_unregistered(self):
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

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
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

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

    def test_answer_invalid_request(self):
        from py3oauth2.errors import InvalidRequest
        from py3oauth2.provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        client = self.make_client()
        req = self.target.from_dict({
            'response_type': 'token',
            'client_id': client.id,
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(provider, 'authorize_client',
                                                  return_value=True))
            stack.enter_context(mock.patch.object(client, 'get_redirect_uri',
                                                  return_value=None))
            stack.enter_context(self.assertRaises(InvalidRequest))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client_redirect_uri_notmatched(self):
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

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
        from py3oauth2.provider import AuthorizationProvider

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
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(provider.normalize_scope(resp.scope),
                         token.get_scope())
        self.assertEqual(resp.state, req.state)
        self.assertTrue(resp.is_redirect())

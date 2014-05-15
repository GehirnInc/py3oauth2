# -*- coding: utf-8 -*-

import contextlib
import json
try:
    from unittest import mock
except ImportError:
    import mock

from . import TestBase


class TestAuthorizationRequest(TestBase):

    def setUp(self):
        super().setUp()

    @property
    def target(self):
        from ..authorizationcodegrant import AuthorizationRequest
        return AuthorizationRequest

    def test_answer_unauthorized_client(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        client = self.make_client()
        req = self.target.from_dict({
            'response_type': 'code',
            'client_id': client.get_id(),
        })

        provider = AuthorizationProvider(self.store)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                AuthorizationProvider, 'authorize_client', return_value=False))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client_unregistered(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)

        req = self.target.from_dict({
            'response_type': 'code',
            'client_id': 'unknown_client_id',
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                AuthorizationProvider, 'authorize_client', return_value=True))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client_redirect_uri_notmatched(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        client = self.make_client(redirect_uri='https://example.com/cb')
        self.store.persist_client(client)

        provider = AuthorizationProvider(self.store)
        req = self.target.from_dict({
            'response_type': 'code',
            'client_id': client.get_id(),
            'redirect_uri': 'https://example.com/unknown_cb'
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                AuthorizationProvider, 'authorize_client', return_value=True))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer(self):
        from ..provider import AuthorizationProvider
        provider = AuthorizationProvider(self.store)
        client = self.make_client()

        req = self.target.from_dict({
            'response_type': 'code',
            'client_id': client.get_id(),
            'state': 'state',
        })

        with mock.patch.object(
                AuthorizationProvider, 'authorize_client', return_value=True):
            resp = req.answer(provider, self.owner)

        resp.validate()

        self.assertIsInstance(resp, req.response)
        self.assertEqual(req.state, resp.state)
        code = self.store.get_authorization_code(resp.code)
        self.assertIsNotNone(code)
        self.assertEqual(len(code.get_code()), 40)
        self.assertTrue(resp.is_redirect())


class TestAccessTokenRequest(TestBase):

    def setUp(self):
        super().setUp()

    @property
    def target(self):
        from ..authorizationcodegrant import AccessTokenRequest
        return AccessTokenRequest

    def test_answer_access_denied_unknown_code(self):
        from ..message import AccessDenied
        from ..provider import AuthorizationProvider

        client = self.make_client()
        req = self.target.from_dict({
            'grant_type': 'authorization_code',
            'code': 'unknown_authorization_code',
            'client_id': client.get_id(),
        })

        provider = AuthorizationProvider(self.store)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                AuthorizationProvider, 'authorize_client', return_value=True))
            stack.enter_context(self.assertRaises(AccessDenied))

            req.answer(provider, self.owner)

    def test_answer_access_denied_used_code(self):
        from ..message import AccessDenied
        from ..provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)

        client = self.make_client()
        owner = self.make_owner()
        authcode = self.make_authcode(client, owner)
        authcode.mark_as_used()

        req = self.target.from_dict({
            'grant_type': 'authorization_code',
            'code': authcode.get_code(),
            'client_id': client.get_id(),
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=True))
            stack.enter_context(self.assertRaises(AccessDenied))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client_unregistered(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        authcode = self.make_authcode(self.make_client(), self.make_owner())

        req = self.target.from_dict({
            'grant_type': 'authorization_code',
            'code': authcode.get_code(),
            'client_id': 'unknown_client_id',
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=True))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client(self):
        from ..message import UnauthorizedClient
        from ..provider import AuthorizationProvider

        client = self.make_client()
        authcode = self.make_authcode(client, self.make_owner())

        provider = AuthorizationProvider(self.store)
        req = self.target.from_dict({
            'grant_type': 'authorization_code',
            'code': authcode.get_code(),
            'client_id': client.get_id(),
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=False))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer(self):
        from ..provider import AuthorizationProvider

        client = self.make_client()
        owner = self.make_owner()
        authcode = self.make_authcode(client, owner)

        provider = AuthorizationProvider(self.store)
        req = self.target.from_dict({
            'grant_type': 'authorization_code',
            'code': authcode.get_code(),
            'client_id': client.get_id(),
        })

        with mock.patch.object(provider, 'authorize_client',
                               return_value=True):
            resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.response)
        token = self.store.get_access_token(resp.access_token)
        self.assertIsNotNone(token)
        self.assertEqual(len(token.get_token()),
                         provider.store.get_access_token_length())
        self.assertFalse(resp.is_redirect())
        self.assertEqual(resp.get_content_type(), 'text/json;charset=utf8')
        self.assertEqual(
            json.loads(resp.get_response_body()),
            json.loads(resp.to_json()))

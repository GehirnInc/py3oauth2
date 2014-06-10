# -*- coding: utf-8 -*-

import contextlib
import json

from py3oauth2.tests import (
    mock,
    TestBase,
)


class TestAuthorizationRequest(TestBase):

    def setUp(self):
        super().setUp()

    @property
    def target(self):
        from py3oauth2.authorizationcodegrant import AuthorizationRequest
        return AuthorizationRequest

    def test_answer_unauthorized_client(self):
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)

        req = self.target()
        req.update({
            'response_type': 'code',
            'client_id': 'unknown_client_id',
        })

        with self.assertRaises(UnauthorizedClient):
            req.answer(provider, self.owner)

    def test_answer_invalid_request(self):
        from py3oauth2.errors import InvalidRequest
        from py3oauth2.provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        client = self.make_client()
        req = self.target()
        req.update({
            'response_type': 'code',
            'client_id': client.id,
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(client, 'get_redirect_uri',
                                                  return_value=None))
            stack.enter_context(self.assertRaises(InvalidRequest))

            req.answer(provider, self.owner)

    def test_answer_unauthorized_client_redirect_uri_notmatched(self):
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

        client = self.make_client(redirect_uri='https://example.com/cb')
        self.store.persist_client(client)

        provider = AuthorizationProvider(self.store)
        req = self.target()
        req.update({
            'response_type': 'code',
            'client_id': client.get_id(),
            'redirect_uri': 'https://example.com/unknown_cb'
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer_store_raises_error_exception(self):
        from py3oauth2.errors import AccessDenied
        from py3oauth2.provider import AuthorizationProvider

        self.store.issue_authorization_code =\
            mock.Mock(side_effect=AccessDenied)
        provider = AuthorizationProvider(self.store)

        client = self.make_client()

        req = self.target()
        req.update({
            'response_type': 'code',
            'client_id': client.get_id(),
            'state': 'state',
        })

        try:
            req.answer(provider, self.owner)
        except AccessDenied as why:
            self.assertIs(why.request, req)
        else:
            self.fail()

    def test_answer(self):
        from py3oauth2.provider import AuthorizationProvider
        provider = AuthorizationProvider(self.store)
        client = self.make_client()

        req = self.target()
        req.update({
            'response_type': 'code',
            'client_id': client.get_id(),
            'state': 'state',
        })

        resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.response)
        self.assertEqual(req.state, resp.state)
        code = self.store.get_authorization_code(resp.code)
        self.assertIsNotNone(code)
        self.assertTrue(resp.is_redirect())


class TestAccessTokenRequest(TestBase):

    def setUp(self):
        super().setUp()

    @property
    def target(self):
        from py3oauth2.authorizationcodegrant import AccessTokenRequest
        return AccessTokenRequest

    def test_answer_access_denied_unknown_code(self):
        from py3oauth2.errors import AccessDenied
        from py3oauth2.provider import AuthorizationProvider

        client = self.make_client()
        req = self.target()
        req.update({
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
        from py3oauth2.errors import AccessDenied
        from py3oauth2.provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)

        client = self.make_client()
        owner = self.make_owner()
        authcode = self.make_authcode(client, owner)
        authcode.mark_as_used()

        req = self.target()
        req.update({
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
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

        provider = AuthorizationProvider(self.store)
        authcode = self.make_authcode(self.make_client(), self.make_owner())

        req = self.target()
        req.update({
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
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

        client = self.make_client()
        authcode = self.make_authcode(client, self.make_owner())

        provider = AuthorizationProvider(self.store)
        req = self.target()
        req.update({
            'grant_type': 'authorization_code',
            'code': authcode.get_code(),
            'client_id': client.get_id(),
        })

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                provider, 'authorize_client', return_value=False))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer_store_raises_error_exception(self):
        from py3oauth2.errors import AccessDenied
        from py3oauth2.provider import AuthorizationProvider

        self.store.issue_access_token = mock.Mock(side_effect=AccessDenied)
        client = self.make_client()
        owner = self.make_owner()
        authcode = self.make_authcode(client, owner)

        provider = AuthorizationProvider(self.store)
        req = self.target()
        req.update({
            'grant_type': 'authorization_code',
            'code': authcode.get_code(),
            'client_id': client.get_id(),
        })

        with mock.patch.object(provider, 'authorize_client',
                               return_value=True):
            try:
                req.answer(provider, self.owner)
            except AccessDenied as why:
                self.assertIs(why.request, req)

    def test_answer(self):
        from py3oauth2.provider import AuthorizationProvider

        client = self.make_client()
        owner = self.make_owner()
        authcode = self.make_authcode(client, owner)

        provider = AuthorizationProvider(self.store)
        req = self.target()
        req.update({
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
        self.assertFalse(resp.is_redirect())
        self.assertEqual(resp.get_content_type(), 'text/json;charset=utf8')
        self.assertEqual(
            json.loads(resp.get_response_body()),
            json.loads(resp.to_json()))

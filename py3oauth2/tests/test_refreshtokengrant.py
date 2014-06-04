# -*- coding: utf-8 -*-

import contextlib
import uuid

from examples.models import (
    Owner,
    Store,
)

from py3oauth2.refreshtokengrant import RefreshTokenRequest
from py3oauth2.tests import (
    BlindAuthorizationProvider,
    mock,
    TestBase,
)


class TestRefreshTokenRequest(TestBase):

    def setUp(self):
        self.store = Store()

        self.client = self.make_client()
        self.store.persist_client(self.client)
        self.owner = Owner(str(uuid.uuid4()))
        self.access_token = self.store.issue_access_token(self.client,
                                                          self.owner,
                                                          {'view', 'write'})

    def test_answer_access_denied(self):
        from py3oauth2.errors import AccessDenied

        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': 'unknown_refresh_token',
        })

        provider = BlindAuthorizationProvider(self.store)
        with self.assertRaises(AccessDenied):
            req.answer(provider, self.owner)

    def test_answer_unauthorized_client(self):
        from py3oauth2.errors import UnauthorizedClient
        from py3oauth2.provider import AuthorizationProvider

        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': self.access_token.get_refresh_token(),
        })

        provider = AuthorizationProvider(self.store)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(provider, 'authorize_client',
                                                  return_value=False))
            stack.enter_context(self.assertRaises(UnauthorizedClient))

            req.answer(provider, self.owner)

    def test_answer(self):
        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': self.access_token.get_refresh_token(),
        })

        provider = BlindAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)

        self.assertIsInstance(resp, req.response)

        token = self.store.get_access_token(resp.access_token)
        self.assertIsNotNone(token)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(provider.normalize_scope(resp.scope),
                         token.get_scope())

    def test_answer_invalid_scope_1(self):
        from py3oauth2.errors import AccessDenied

        provider = BlindAuthorizationProvider(self.store)

        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': self.access_token.get_refresh_token(),
            'scope': 'view write admin',
        })
        with self.assertRaises(AccessDenied):
            req.answer(provider, self.owner)

    def test_answer_invalid_scope_2(self):
        from py3oauth2.errors import AccessDenied

        access_token = self.store.issue_access_token(self.client,
                                                     self.owner,
                                                     {'write'})
        provider = BlindAuthorizationProvider(self.store)

        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': access_token.get_refresh_token(),
            'scope': 'view',
        })
        with self.assertRaises(AccessDenied):
            req.answer(provider, self.owner)

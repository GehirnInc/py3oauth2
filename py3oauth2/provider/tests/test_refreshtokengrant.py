# -*- coding: utf-8 -*-

import uuid

from . import (
    BlindAuthorizationProvider,
    BrokenAuthorizationProvider,
    DummyAuthorizationProvider,
    Owner,
    Store,
    TestBase,
)
from .. import utils
from ..refreshtokengrant import RefreshTokenRequest


class TestRefreshTokenRequest(TestBase):

    def setUp(self):
        self.store = Store()

        self.client = self.make_client()
        self.store.persist_client(self.client)

        self.owner = Owner(str(uuid.uuid4()))

        self.access_token = self.store.persist_access_token(
            self.client, self.owner,
            utils.generate_random_string(
                self.store.get_access_token_length(),
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
            ),
            'view write',
            utils.generate_random_string(
                self.store.get_refresh_token_length(),
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
            ),

        )

    def test_answer_access_denied(self):
        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': 'unknown_refresh_token',
        })

        provider = BlindAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'access_denied')

    def test_answer_unauthorized_client(self):
        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': self.access_token.get_refresh_token(),
        })

        provider = DummyAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_server_error(self):
        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': self.access_token.get_refresh_token(),
        })

        provider = BrokenAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'server_error')

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
        self.assertEqual(
            len(token.get_token()),
            self.store.get_access_token_length())
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(resp.scope, token.get_scope())

    def test_answer_invalid_scope_1(self):
        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': self.access_token.get_refresh_token(),
            'scope': 'view write admin',
        })

        provider = BlindAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)

        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'access_denied')

    def test_answer_invalid_scope_2(self):
        access_token = self.store.persist_access_token(
            self.client, self.owner,
            utils.generate_random_string(
                self.store.get_access_token_length(),
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
            ),
            None,
            utils.generate_random_string(
                self.store.get_refresh_token_length(),
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
            ),

        )

        req = RefreshTokenRequest.from_dict({
            'grant_type': 'refresh_token',
            'refresh_token': access_token.get_refresh_token(),
            'scope': 'view',
        })

        provider = BlindAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)

        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'access_denied')

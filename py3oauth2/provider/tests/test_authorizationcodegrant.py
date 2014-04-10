# -*- coding: utf-8 -*-

import unittest
import uuid

from ..authorizationcodegrant import (
    AccessTokenRequest,
    AuthorizationRequest,
)

from . import (
    BlindAuthorizationProvider,
    BrokenAuthorizationProvider,
    Client,
    DummyAuthorizationProvider,
    Owner,
    Store,
)
from .. import utils
from ..message import UnauthorizedClient


class TestAuthorizationRequest(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        self.client = Client(str(uuid.uuid4()))
        self.store.persist_client(self.client)

        self.owner = Owner(str(uuid.uuid4()))

    def test_answer_unauthorized_client_1(self):
        provider = BlindAuthorizationProvider(self.store)

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': 'unknown_client_id',
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, AuthorizationRequest.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_unauthorized_client_2(self):
        provider = DummyAuthorizationProvider(self.store)

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, AuthorizationRequest.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_server_error(self):
        provider = BrokenAuthorizationProvider(self.store)

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'server_error')


class TestAccessTokenRequest(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        self.client = Client(str(uuid.uuid4()))
        self.store.persist_client(self.client)

        self.owner = Owner(str(uuid.uuid4()))

        self.authcode = self.store.persist_authorization_code(
            self.client, self.owner,
            utils.generate_random_string(
                self.store.get_authorization_code_length(),
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
            ),
            None,
        )

    def test_answer_access_denied_1(self):
        req = AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': 'unknown_authorization_code',
            'client_id': self.client.get_id(),
        })

        provider = BlindAuthorizationProvider(self.store)
        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'access_denied')

    def test_answer_access_denied_2(self):
        provider = BlindAuthorizationProvider(self.store)
        self.authcode.mark_as_used()

        req = AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': self.authcode.get_code(),
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'access_denied')

    def test_answer_unauthorized_client_1(self):
        provider = BlindAuthorizationProvider(self.store)

        req = AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': self.authcode.get_code(),
            'client_id': 'unknown_client_id',
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_unauthorized_client_2(self):
        provider = DummyAuthorizationProvider(self.store)

        req = AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': self.authcode.get_code(),
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_server_error(self):
        provider = BrokenAuthorizationProvider(self.store)

        req = AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': self.authcode.get_code(),
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'server_error')

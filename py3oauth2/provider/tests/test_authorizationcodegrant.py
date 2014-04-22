# -*- coding: utf-8 -*-

import json
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

    def test_answer_unauthorized_client_3(self):
        provider = BlindAuthorizationProvider(self.store)

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.get_id(),
            'redirect_uri': 'http://example.com/cb/2'
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, AuthorizationRequest.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_invalid_request(self):
        provider = BlindAuthorizationProvider(self.store)
        self.client.get_redirect_uri = lambda: None

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, AuthorizationRequest.err_response)
        self.assertEqual(resp.error, 'invalid_request')

    def test_answer_server_error(self):
        provider = BrokenAuthorizationProvider(self.store)

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.get_id(),
        })

        resp = req.answer(provider, self.owner)
        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'server_error')
        self.assertTrue(resp.is_redirect())

    def test_answer(self):
        provider = BlindAuthorizationProvider(self.store)

        req = AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.get_id(),
            'state': 'state',
        })

        resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.response)
        self.assertEqual(req.state, resp.state)
        code = self.store.get_authorization_code(resp.code)
        self.assertIsNotNone(code)
        self.assertEqual(len(code.get_code()), 40)
        self.assertTrue(resp.is_redirect())


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
        self.assertFalse(resp.is_redirect())
        self.assertEqual(resp.get_content_type(), 'text/json;charset=utf8')
        self.assertEqual(
            json.loads(resp.get_response_body()),
            json.loads(resp.to_json()))

    def test_answer(self):
        provider = BlindAuthorizationProvider(self.store)

        req = AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': self.authcode.get_code(),
            'client_id': self.client.get_id(),
        })

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

# -*- coding: utf-8 -*-

import random
import string
import unittest
import uuid

from .. import (
    authorizationcodegrant,
    message,
)
from . import (
    BlindAuthorizationProvider,
    Client,
    Owner,
    Store,
    Request as TestRequest,
)


class TestAuthorizationProvider(unittest.TestCase):

    def setUp(self):
        self.store = Store()
        self.provider = BlindAuthorizationProvider(self.store)

        self.client = Client(str(uuid.uuid4()))
        self.store.persist_client(self.client)

        self.owner = Owner(str(uuid.uuid4()))

    def test_generate_authorization_code(self):
        pool = string.ascii_letters + string.digits

        code = self.provider.generate_authorization_code()
        self.assertEqual(len(code), self.store.get_authorization_code_length())
        self.assertTrue(all(map(lambda c: c in pool, code)))

    def test_generate_access_token(self):
        pool = string.ascii_letters + string.digits

        code = self.provider.generate_access_token()
        self.assertEqual(len(code), self.store.get_access_token_length())
        self.assertTrue(all(map(lambda c: c in pool, code)))

    def test_generate_refresh_token(self):
        pool = string.ascii_letters + string.digits

        code = self.provider.generate_refresh_token()
        self.assertEqual(len(code), self.store.get_refresh_token_length())
        self.assertTrue(all(map(lambda c: c in pool, code)))

    def test_handle_request_authorizationcodegrant(self):
        pool = string.ascii_letters + string.digits
        prereq = {
            'response_type': 'code',
            'client_id': self.client.get_id(),
            'state': ''.join(random.choice(pool) for _ in range(40))
        }

        preresp = self.provider.handle_request(prereq)
        self.assertIsInstance(
            preresp.request,
            authorizationcodegrant.AuthorizationRequest)
        self.assertIsInstance(
            preresp,
            authorizationcodegrant.AuthorizationRequest.response)

        authcode = self.store.get_authorization_code(preresp.code)
        self.assertIsNotNone(authcode)
        self.assertEqual(preresp.state, prereq['state'])

        req = {
            'grant_type': 'authorization_code',
            'code': preresp.code,
            'client_id': self.client.get_id(),
        }
        resp = self.provider.handle_request(req, self.owner)

        self.assertIsInstance(
            resp.request,
            authorizationcodegrant.AccessTokenRequest)
        self.assertIsInstance(resp, message.AccessTokenResponse)

        token = self.store.get_access_token(resp.access_token)
        self.assertIsNotNone(token)
        self.assertEqual(len(token.get_token()), 40)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(resp.scope, token.get_scope())

    def test_handle_request_not_found(self):
        req = {}
        with self.assertRaises(ValueError):
            self.provider.handle_request(req)

    def test_handle_request_invalid_request(self):
        req = {
            'response_type': 'code',
            'client_id': 12345,
        }

        resp = self.provider.handle_request(req)
        self.assertIsInstance(resp.request,
                              authorizationcodegrant.AuthorizationRequest)
        self.assertIsInstance(
            resp,
            authorizationcodegrant.AuthorizationRequest.err_response)
        self.assertEqual(resp.error, 'invalid_request')

    def test_handle_request_server_error(self):
        req = {
            'grant_type': 'test',
        }

        resp = self.provider.handle_request(req)
        self.assertIsInstance(resp.request, TestRequest)
        self.assertIsInstance(resp, TestRequest.err_response)
        self.assertEqual(resp.error, 'server_error')

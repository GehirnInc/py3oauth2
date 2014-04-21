# -*- coding: utf-8 -*-

import random
import string
import unittest
import uuid

from .. import (
    authorizationcodegrant,
    AuthorizationProvider,
    message,
    ResourceProvider,
)
from ..exceptions import (
    AccessDenied,
    ErrorResponse,
    UnknownRequest,
)
from ..interfaces import ClientType
from . import (
    BlindAuthorizationProvider,
    Client,
    DummyResourceProvider,
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

    def test_authorize_client(self):
        inst = AuthorizationProvider(self.store)
        with self.assertRaises(NotImplementedError):
            inst.authorize_client(self.client)

    def test_validate_redirect_uri(self):
        self.client.get_redirect_uri = lambda: None

        inst = AuthorizationProvider(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(self.client, 'http://example.com/')
        )

        self.client.get_type = lambda: ClientType.PUBLIC
        self.assertFalse(
            inst.validate_redirect_uri(self.client, 'http://example.com/')
        )

        self.client.get_redirect_uri = lambda: 'http://example.com/ab?a=b'
        self.assertTrue(inst.validate_redirect_uri(
            self.client, 'http://example.com/ab/?a=b'
        ))

        self.assertFalse(
            inst.validate_redirect_uri(self.client, 'https://example.com/')
        )

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

    def test_decode_request_authorizationcodegrant(self):
        pool = string.ascii_letters + string.digits
        prereq = {
            'response_type': 'code',
            'client_id': self.client.get_id(),
            'state': ''.join(random.choice(pool) for _ in range(40))
        }

        prerequest = self.provider.decode_request(prereq)
        self.assertIsInstance(
            prerequest,
            authorizationcodegrant.AuthorizationRequest
        )

        preresp = self.provider.handle_request(prerequest)
        self.assertIsInstance(
            preresp,
            authorizationcodegrant.AuthorizationRequest.response
        )

        authcode = self.store.get_authorization_code(preresp.code)
        self.assertIsNotNone(authcode)
        self.assertEqual(preresp.state, prereq['state'])

        req = {
            'grant_type': 'authorization_code',
            'code': preresp.code,
            'client_id': self.client.get_id(),
        }
        request = self.provider.decode_request(req)
        self.assertIsInstance(
            request,
            authorizationcodegrant.AccessTokenRequest
        )

        resp = self.provider.handle_request(request, self.owner)
        self.assertIsInstance(resp, message.AccessTokenResponse)

        token = self.store.get_access_token(resp.access_token)
        self.assertIsNotNone(token)
        self.assertEqual(len(token.get_token()), 40)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(resp.scope, token.get_scope())

    def test_decode_request_not_found(self):
        req = {}
        with self.assertRaises(UnknownRequest):
            self.provider.decode_request(req)

    def test_decode_request_invalid_request(self):
        req = {
            'response_type': 'code',
            'client_id': 12345,
        }

        with self.assertRaises(ErrorResponse):
            self.provider.decode_request(req)

        try:
            self.provider.decode_request(req)
        except ErrorResponse as why:
            self.assertIsInstance(why.response.request,
                                  authorizationcodegrant.AuthorizationRequest)
            self.assertIsInstance(
                why.response,
                authorizationcodegrant.AuthorizationRequest.err_response
            )
            self.assertEqual(why.response.error, 'invalid_request')

    def test_handle_request_server_error(self):
        req = {
            'grant_type': 'test',
        }

        request = self.provider.decode_request(req)
        self.assertIsInstance(request, TestRequest)

        with self.assertRaises(ErrorResponse):
            self.provider.handle_request(request, self.owner)

        try:
            self.provider.handle_request(request, self.owner)
        except ErrorResponse as why:
            self.assertIsInstance(why.response, TestRequest.err_response)
            self.assertEqual(why.response.error, 'server_error')


class TestResourceProvider(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        client = Client(str(uuid.uuid4()))
        self.store.persist_client(client)

        owner = Owner(str(uuid.uuid4()))

        pool = string.ascii_letters + string.digits
        token = ''.join(random.choice(pool) for _ in range(40))
        self.token = self.store.persist_access_token(
            client, owner, token, 'view edit', None,
        )

    def test_get_access_token(self):
        inst = ResourceProvider(self.store)
        with self.assertRaises(NotImplementedError):
            inst.get_access_token()

    def test_dummy_get_access_token(self):
        inst = DummyResourceProvider(self.store,
                                     self.token.get_token(), 'bearer')
        self.assertEqual(
            inst.get_access_token(),
            (self.token.get_token(), 'bearer'),
        )

    def test_authorize(self):
        inst = DummyResourceProvider(self.store,
                                     self.token.get_token(), 'bearer')
        self.assertTrue(inst.authorize({'view'}))
        self.assertTrue(inst.authorize({'edit'}))
        self.assertTrue(inst.authorize({'view', 'edit'}))
        with self.assertRaises(AccessDenied):
            inst.authorize({'delete'})

    def test_authorize_unknown_token(self):
        inst = DummyResourceProvider(self.store, 'unknowntoken', 'bearer')
        with self.assertRaises(AccessDenied):
            inst.authorize(set())

    def test_authorize_expired(self):
        self.token.expires_in = 0
        inst = DummyResourceProvider(self.store,
                                     self.token.get_token(), 'bearer')
        with self.assertRaises(AccessDenied):
            inst.authorize({'view'})

    def test_authorize_unknown_token_type(self):
        inst = DummyResourceProvider(self.store, self.token.get_token(), 'foo')
        with self.assertRaises(AccessDenied):
            inst.authorize({'view'})

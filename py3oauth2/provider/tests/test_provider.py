# -*- coding: utf-8 -*-

import uuid

from ..exceptions import (
    ErrorResponse,
)
from ..interfaces import ClientType
from . import (
    BlindAuthorizationProvider,
    DummyResourceProvider,
    Store,
    TestBase,
)


class AuthorizationProviderTest(TestBase):

    def setUp(self):
        self.store = Store()

    @property
    def target(self):
        from ..provider import AuthorizationProvider
        return AuthorizationProvider

    def make_target(self, store):
        return self.target(store)

    def test_constructor(self):
        inst = self.make_target(self.store)
        self.assertIs(inst.store, self.store)

    def test_add_authorization_handler(self):
        from ..message import Request
        inst = self.make_target(self.store)
        inst.add_authorization_handler(
            ('id_token', 'code', 'token'),
            Request)

        self.assertIn(('code', 'id_token', 'token'), inst.authz_handlers)
        self.assertIs(
            inst.authz_handlers[('code', 'id_token', 'token')],
            Request)

    def test_add_token_handler(self):
        from ..message import Request
        inst = self.make_target(self.store)
        inst.add_token_handler('refresh_token', Request)

        self.assertIn('refresh_token', inst.token_handlers)
        self.assertIs(inst.token_handlers['refresh_token'], Request)

    def test_authorize_client(self):
        inst = self.make_target(self.store)
        with self.assertRaises(NotImplementedError):
            inst.authorize_client(object())

    def test_validate_redirect_uri_confidential_registered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.CONFIDENTIAL)

        inst = self.make_target(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(client, 'https://example.com/cb'))

    def test_validate_redirect_uri_confidential_unregistered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.CONFIDENTIAL)

        inst = self.make_target(self.store)
        self.assertFalse(
            inst.validate_redirect_uri(client, 'https://cb.example.com/'))

    def test_validate_redirect_uri_confidential_empty(self):
        client = self.make_client(
            redirect_uri='',
            type=ClientType.CONFIDENTIAL)

        inst = self.make_target(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(client, 'https://example.com/cb'))

    def test_validate_redirect_uri_public_registered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.PUBLIC)

        inst = self.make_target(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(client, 'https://example.com/cb'))

    def test_validate_redirect_uri_public_unregistered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.PUBLIC)

        inst = self.make_target(self.store)
        self.assertFalse(
            inst.validate_redirect_uri(client, 'https://cb.example.com/'))

    def test_validate_redirect_uri_contains_query(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb?foo=bar',
            type=ClientType.PUBLIC)

        inst = self.make_target(self.store)
        self.assertTrue(inst.validate_redirect_uri(
            client, 'https://example.com/cb?bar=baz'
        ))

    def test_generate_authorization_code(self):
        inst = self.make_target(self.store)
        code = inst.generate_authorization_code()
        self.assertEqual(len(code),
                         self.store.get_authorization_code_length())

        self.assertRegex(code, r'^[a-zA-Z0-9]+$')

    def test_generate_access_token(self):
        inst = self.make_target(self.store)
        token = inst.generate_access_token()
        self.assertEqual(len(token),
                         self.store.get_access_token_length())
        self.assertRegex(token, r'^[a-zA-Z0-9]+$')

    def test_generate_refresh_token(self):
        inst = self.make_target(self.store)
        token = inst.generate_refresh_token()
        self.assertEqual(len(token),
                         self.store.get_refresh_token_length())
        self.assertRegex(token, r'^[a-zA-Z0-9]+$')

    def test_decode_authorize_request(self):
        from .. import authorizationcodegrant
        client = self.make_client()

        inst = self.make_target(self.store)
        ret = inst.decode_authorize_request({
            'response_type': 'code',
            'client_id': client.id,
        })

        self.assertIsInstance(ret, authorizationcodegrant.AuthorizationRequest)
        self.assertEqual(ret.response_type, 'code')
        self.assertEqual(ret.client_id, client.id)

    def test_decode_authorize_request_unsupported(self):
        client = self.make_client()

        inst = self.make_target(self.store)
        try:
            inst.decode_authorize_request({
                'response_type': 'code token',
                'client_id': client.id,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_response_type')
        else:
            self.fail()

    def test_decode_authorize_request_unsupported_with_state(self):
        client = self.make_client()

        state = str(uuid.uuid4())
        inst = self.make_target(self.store)
        try:
            inst.decode_authorize_request({
                'response_type': 'code token',
                'client_id': client.id,
                'state': state,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_response_type')
            self.assertEqual(resp.get('state'), state)
        else:
            self.fail()

    def test_decode_authorize_request_unsupported_missing(self):
        # NOTES: missing `response_type`
        client = self.make_client()

        state = str(uuid.uuid4())
        inst = self.make_target(self.store)
        try:
            inst.decode_authorize_request({
                'state': state,
                'client_id': client.id,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_response_type')
            self.assertEqual(resp.get('state'), state)
        else:
            self.fail()

    def test_decode_authorize_request_invalid(self):
        # NOTES: missing `client_id`
        state = str(uuid.uuid4())
        inst = self.make_target(self.store)
        try:
            inst.decode_authorize_request({
                'response_type': 'code',
                'state': state,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'invalid_request')
            self.assertEqual(resp.get('state'), state)
        else:
            self.fail()

    def test_decode_token_request(self):
        from .. import authorizationcodegrant
        client = self.make_client()

        inst = self.make_target(self.store)
        ret = inst.decode_token_request({
            'grant_type': 'authorization_code',
            'client_id': client.id,
            'code': inst.generate_authorization_code(),
        })

        self.assertIsInstance(ret, authorizationcodegrant.AccessTokenRequest)
        self.assertEqual(ret.grant_type, 'authorization_code')

    def test_decode_token_request_unsupported(self):
        inst = self.make_target(self.store)
        try:
            inst.decode_token_request({
                'grant_type': 'unknown_grant_type',
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_grant_type')
        else:
            self.fail()

    def test_decode_token_request_unsupported_with_state(self):
        state = str(uuid.uuid4())
        inst = self.make_target(self.store)
        try:
            inst.decode_token_request({
                'grant_type': 'unknown_grant_type',
                'state': state,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_grant_type')
            self.assertEqual(resp.get('state'), state)
        else:
            self.fail()

    def test_decode_token_request_unsupported_missing(self):
        # NOTES: missing `grant_type`
        state = str(uuid.uuid4())
        inst = self.make_target(self.store)
        try:
            inst.decode_token_request({
                'state': state,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_grant_type')
            self.assertEqual(resp.get('state'), state)
        else:
            self.fail()

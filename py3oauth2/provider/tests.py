# -*- coding: utf-8 -*-

import unittest
import uuid

from . import (
    authorizationcodegrant,
    implicitgrant,
    message,
)
from .provider import AuthorizationProvider
from .store import IStore


class Owner:

    def __init__(self, id):
        self.id = id


class Client:

    def __init__(self, id):
        self.id = id

    def get_id(self):
        return self.id


class AccessToken:

    def __init__(self, owner, token, expires_in, scope):
        self.owner = owner
        self.token = token
        self.expires_in = expires_in
        self.scope = scope

    def get_token(self):
        return self.token

    def get_type(self):
        return 'bearer'

    def get_expires_in(self):
        return self.expires_in

    def get_refresh_token(self):
        return None

    def get_scope(self):
        return self.scope


class AuthorizationCode:

    def __init__(self, client, owner, code, scope):
        self.client = client
        self.owner = owner
        self.code = code
        self.scope = scope
        self.used = False

    def get_client(self):
        return self.client

    def get_owner(self):
        return self.owner

    def get_scope(self):
        return self.scope

    def mark_as_used(self):
        self.used = True

    @property
    def is_used(self):
        return self.used

    def get_code(self):
        return self.code


class MemoryStore(IStore):

    def __init__(self):
        self.clients = {}
        self.access_tokens = {}
        self.authorization_codes = {}

    def get_client(self, client_id):
        try:
            return self.clients[client_id]
        except KeyError:
            raise ValueError

    def persist_client(self, client):
        self.clients[client.id] = client

    def persist_access_token(self, client, owner, token, scope):
        if client not in self.access_tokens:
            self.access_tokens[client] = {}

        tokenobj = AccessToken(owner, token, 0, scope)
        self.access_tokens[client][token] = tokenobj
        return tokenobj

    def persist_authorization_code(self, client, owner, code, scope):
        codeobj = AuthorizationCode(client, owner, code, scope)
        self.authorization_codes[code] = codeobj
        return codeobj

    def discard_authorization_code(self, client, code):
        if client not in self.authorization_codes:
            raise ValueError

        self.authorization_codes[client].pop(code)

    def get_authorization_code(self, code):
        try:
            return self.authorization_codes[code]
        except KeyError:
            raise ValueError()

    """
    def persist_refresh_token(self, client, access_token):
        raise NotImplementedError

    def discard_refresh_token(self, client, refresh_token):
        raise NotImplementedError
    """


class DummyAuthorizationProvider(AuthorizationProvider):

    def validate_client(self, client):
        try:
            self.store.get_client(client.id)
        except ValueError:
            return False
        else:
            return True


class TestAuthorizationProvider(unittest.TestCase):

    def setUp(self):
        super(TestAuthorizationProvider, self).setUp()

        self.store = MemoryStore()
        self.owner = Owner(str(uuid.uuid4()))

        self.client = Client(str(uuid.uuid4()))
        self.store.persist_client(self.client)

    def test_handle_request(self):
        provider = DummyAuthorizationProvider(self.store)

        # _handle_authcode_code
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
        })
        resp = provider.handle_request(req, self.owner)
        self.assertEqual(
            resp.code,
            list(self.store.authorization_codes.keys())[0])
        self.assertIsNone(resp.state)

        # _handle_implicit_access_token
        req = implicitgrant.Request.from_dict({
            'response_type': 'token',
            'client_id': self.client.id,
        })
        resp = provider.handle_request(req, self.owner)
        self.assertEqual(
            resp.access_token,
            list(self.store.access_tokens[self.client].keys())[0])

        # unsupported_response_type
        req = implicitgrant.Request.from_dict({
            'response_type': 'unknown_response_type',
            'client_id': self.client.id,
        })
        resp = provider.handle_request(req, self.owner)
        self.assertEqual(resp.error, 'unsupported_response_type')

        # _handle_authcode_token
        prereq = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
        })
        preresp = provider.handle_request(prereq, self.owner)

        req = authorizationcodegrant.AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': preresp.code,
            'client_id': self.client.id,
        })
        resp = provider.handle_request(req)
        self.assertIn(
            resp.access_token,
            self.store.access_tokens[self.client].keys())

        # unsupported_grant_type
        req = authorizationcodegrant.AccessTokenRequest.from_dict({
            'grant_type': 'unknown_grant_type',
            'code': preresp.code,
            'client_id': self.client.id,
        })
        resp = provider.handle_request(req)
        self.assertEqual(resp.error, 'unsupported_grant_type')

        # invalid_request
        DummyRequest = type('DummyRequest', (message.Request, ), {
            'response': None,
            'err_response': message.ErrorResponse,
        })
        req = DummyRequest()
        resp = provider.handle_request(req)
        self.assertEqual(resp.error, 'invalid_request')

    def test_handle_authcode_code(self):
        provider = DummyAuthorizationProvider(self.store)
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
        })
        resp = provider._handle_authcode_code(req, self.owner)
        self.assertEqual(
            resp.code,
            list(self.store.authorization_codes.keys())[0])
        self.assertIsNone(resp.state)

    def test_handle_authcode_code_with_state(self):
        provider = DummyAuthorizationProvider(self.store)
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
            'state': str(uuid.uuid4()),
        })
        resp = provider._handle_authcode_code(req, self.owner)
        self.assertEqual(
            resp.code,
            list(self.store.authorization_codes.keys())[0])
        self.assertEqual(resp.state, req.state)

    def test_handle_authcode_code_unauthorized_client(self):
        provider = DummyAuthorizationProvider(self.store)
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': 'invalid_client_id',
        })
        resp = provider._handle_authcode_code(req, self.owner)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_handle_authcode_token(self):
        provider = DummyAuthorizationProvider(self.store)

        prereq = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
        })
        preresp = provider._handle_authcode_code(prereq, self.owner)

        req = authorizationcodegrant.AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': preresp.code,
            'client_id': self.client.id,
        })
        resp = provider._handle_authcode_token(req)
        self.assertEqual(
            resp.access_token,
            list(self.store.access_tokens[self.client].keys())[0])

    def test_handle_authcode_token_unauthorized_client(self):
        provider = DummyAuthorizationProvider(self.store)

        prereq = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
        })
        preresp = provider._handle_authcode_code(prereq, self.owner)

        req = authorizationcodegrant.AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': preresp.code,
            'client_id': 'dummy_client_id',
        })
        resp = provider._handle_authcode_token(req)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_handle_authcode_token_access_denied(self):
        provider = DummyAuthorizationProvider(self.store)
        req = authorizationcodegrant.AccessTokenRequest.from_dict({
            'grant_type': 'authorization_code',
            'code': 'dummy_authorization_code',
            'client_id': self.client.id,
        })
        resp = provider._handle_authcode_token(req)
        self.assertEqual(resp.error, 'access_denied')

    def test_handle_implicit_access_token(self):
        provider = DummyAuthorizationProvider(self.store)
        req = implicitgrant.Request.from_dict({
            'response_type': 'token',
            'client_id': self.client.id,
        })
        resp = provider._handle_implicit_access_token(req, self.owner)
        self.assertEqual(
            resp.access_token,
            list(self.store.access_tokens[self.client].keys())[0])

    def test_handle_implicit_access_token_unauthorized_client(self):
        provider = DummyAuthorizationProvider(self.store)
        req = implicitgrant.Request.from_dict({
            'response_type': 'token',
            'client_id': 'dummy_client_id',
        })
        resp = provider._handle_implicit_access_token(req, self.owner)
        self.assertEqual(resp.error, 'unauthorized_client')

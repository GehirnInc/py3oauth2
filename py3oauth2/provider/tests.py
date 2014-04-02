# -*- coding: utf-8 -*-

import unittest
import uuid

from . import (
    authorizationcodegrant,
    utils,
)
from .provider import AuthorizationProvider
from .store import IStore


class Owner:

    def __init__(self, id):
        self.id = id


class Client:

    def __init__(self, id):
        self.id = id


class AccessToken:

    def __init__(self, owner, token, expires_in):
        self.owner = owner
        self.token = token
        self.expires_in = expires_in


class AuthorizationCode:

    def __init__(self, owner, code, scope):
        self.owner = owner
        self.code = code
        self.scope = scope

    def get_code(self):
        return self.code


class MemoryStore(IStore):

    def __init__(self):
        self.clients = {}
        self.access_tokens = {}
        self.authorization_codes = {}

    def get_client(self, client_id):
        return self.clients[client_id]

    def persist_client(self, client):
        self.clients[client.id] = client

    def persist_access_token(self, client, owner, token, expires_in, scope):
        if client not in self.access_tokens:
            self.access_tokens[client] = {}

        tokenobj = AccessToken(owner, token, expires_in)
        self.access_tokens[client][token] = tokenobj
        return tokenobj

    def persist_authorization_code(self, client, owner, code, scope):
        if client not in self.authorization_codes:
            self.authorization_codes[client] = {}

        codeobj = AuthorizationCode(owner, code, scope)
        self.authorization_codes[client][code] = codeobj
        return codeobj

    def discard_authorization_code(self, client, code):
        if client not in self.authorization_codes:
            raise ValueError

        self.authorization_codes[client].pop(code)

    """
    def persist_refresh_token(self, client, access_token):
        raise NotImplementedError

    def discard_refresh_token(self, client, refresh_token):
        raise NotImplementedError
    """


class TestBase(unittest.TestCase):

    def setUp(self):
        self.store = MemoryStore()

        self.client = Client(str(uuid.uuid4()))
        self.store.persist_client(self.client)

        self.owner = Owner(str(uuid.uuid4()))


class TestAuthorizationCodeFlow(TestBase):

    def test_authorization_code(self):
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
        })

        provider = AuthorizationProvider(self.store)
        resp = provider.issue_authorization_code(self.owner, req)

        self.assertIsInstance(resp,
                              authorizationcodegrant.AuthorizationResponse)
        self.assertIsInstance(resp.code, str)
        self.assertFalse('state' in resp)

    def test_authorization_code_using_state(self):
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'response_type': 'code',
            'client_id': self.client.id,
            'state': utils.generate_random_string(
                20,
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS),
        })

        provider = AuthorizationProvider(self.store)
        resp = provider.issue_authorization_code(self.owner, req)

        self.assertIsInstance(resp,
                              authorizationcodegrant.AuthorizationResponse)
        self.assertIsInstance(resp.code, str)
        self.assertEqual(resp.state, req.state)

    def test_authorization_code_missing_response_type(self):
        req = authorizationcodegrant.AuthorizationRequest.from_dict({
            'client_id': self.client.id,
            'state': utils.generate_random_string(
                20,
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS),
        })

        provider = AuthorizationProvider(self.store)
        resp = provider.issue_authorization_code(self.owner, req)

        self.assertIsInstance(resp,
                              authorizationcodegrant.AuthorizationErrorResponse)
        self.assertEqual(resp.error, 'invalid_request')

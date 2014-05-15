# -*- coding: utf-8 -*-

import unittest
import uuid
from datetime import datetime

from .. import utils
from ..interfaces import (
    ClientType,
    IAccessToken,
    IAuthorizationCode,
    IClient,
    IStore,
)
from .. import message
from ..provider import (
    AuthorizationProvider,
    ResourceProvider,
)


class Owner:

    def __init__(self, id):
        self.id = id


class Client(IClient):

    def __init__(self, id, redirect_uri, type):
        self.id = id
        self.redirect_uri = redirect_uri
        self.type = type

    def get_id(self):
        return self.id

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_type(self):
        return self.type


class AccessToken(IAccessToken):

    def __init__(self, client, owner, token, expires_in, scope,
                 refresh_token=None):
        self.client = client
        self.owner = owner
        self.token = token
        self.expires_in = expires_in
        self.scope = scope
        self.refresh_token = refresh_token
        self.issued_at = datetime.utcnow()

    def get_client(self):
        return self.client

    def get_owner(self):
        return self.owner

    def get_token(self):
        return self.token

    def get_type(self):
        return 'bearer'

    def get_expires_in(self):
        return self.expires_in

    def get_scope(self):
        return self.scope

    def get_refresh_token(self):
        return self.refresh_token

    def get_issued_at(self):
        return self.issued_at


class AuthorizationCode(IAuthorizationCode):

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

    def get_code(self):
        return self.code

    def get_scope(self):
        return self.scope

    def is_used(self):
        return self.used

    def mark_as_used(self):
        self.used = True


class Store(IStore):

    def __init__(self):
        self.clients = dict()
        self.access_tokens = dict()
        self.refresh_tokens = dict()
        self.authorization_codes = dict()

    def persist_client(self, client):
        self.clients[client.get_id()] = client

    def get_client(self, client_id):
        return self.clients.get(client_id)

    def persist_access_token(self, client, owner, token, scope, refresh_token):
        tokenobj =\
            AccessToken(client, owner, token, 3600, scope, refresh_token)
        self.access_tokens[tokenobj.get_token()] = tokenobj
        if tokenobj.get_refresh_token():
            self.refresh_tokens[tokenobj.get_refresh_token()] = tokenobj
        return tokenobj

    def discard_access_token(self, token):
        del self.access_tokens[token.get_token()]

    def get_access_token(self, token):
        return self.access_tokens.get(token)

    def get_access_token_by_refresh_token(self, refresh_token):
        return self.refresh_tokens.get(refresh_token)

    def get_access_token_length(self):
        return 40

    def get_refresh_token_length(self):
        return 40

    def persist_authorization_code(self, client, owner, code, scope):
        codeobj = AuthorizationCode(client, owner, code, scope)
        self.authorization_codes[codeobj.get_code()] = codeobj
        return codeobj

    def get_authorization_code(self, code):
        return self.authorization_codes.get(code)

    def get_authorization_code_length(self):
        return 40


class Response(message.Response):
    param = message.Parameter(str, required=True)


class Request(message.Request):
    response = Response
    err_response = message.ErrorResponse

    grant_type = message.Parameter(str, required=True,
                                   default='test', editable=False)
    response_type = message.Parameter(str)
    response_mode = message.Parameter(str)

    def handle(self, provider, owner):
        return self.response(self)


class BlindAuthorizationProvider(AuthorizationProvider):

    def __init__(self, store):
        super(BlindAuthorizationProvider, self).__init__(store)

        self.add_token_handler('test', Request)

    def authorize_client(self, client):
        return True


class BrokenAuthorizationProvider(BlindAuthorizationProvider):

    def authorize_client(self, client):
        raise RuntimeError


class DummyAuthorizationProvider(BlindAuthorizationProvider):

    def authorize_client(self, client):
        raise message.UnauthorizedClient


class DummyResourceProvider(ResourceProvider):

    def __init__(self, store, token, token_type):
        super(DummyResourceProvider, self).__init__(store)
        self.token = token
        self.token_type = token_type

    def get_access_token(self):
        return (self.token, self.token_type)


class TestBase(unittest.TestCase):

    def setUp(self):
        self.store = Store()
        self.owner = Owner(str(uuid.uuid4()))

    def make_client(self, id=lambda: str(uuid.uuid4()),
                    redirect_uri='https://example.com/cb',
                    type=ClientType.CONFIDENTIAL):
        if callable(id):
            id = id()

        client = Client(id, redirect_uri, type)
        self.store.persist_client(client)
        return client

    def make_authcode(self, client, owner):
        return self.store.persist_authorization_code(
            client, owner,
            utils.generate_random_string(
                self.store.get_authorization_code_length(),
                utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
            ),
            None,
        )

    def make_owner(self):
        return Owner(str(uuid.uuid4()))

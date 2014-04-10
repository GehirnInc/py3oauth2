# -*- coding: utf-8 -*-

from ..interfaces import (
    IAccessToken,
    IAuthorizationCode,
    IClient,
    IStore,
)
from .. import message
from ..provider import AuthorizationProvider


class Owner:

    def __init__(self, id):
        self.id = id


class Client(IClient):

    def __init__(self, id):
        self.id = id

    def get_id(self):
        return self.id


class AccessToken(IAccessToken):

    def __init__(self, client, owner, token, expires_in, scope,
                 refresh_token=None):
        self.client = client
        self.owner = owner
        self.token = token
        self.expires_in = expires_in
        self.scope = scope
        self.refresh_token = refresh_token

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
        tokenobj = AccessToken(client, owner, token, 0, scope, refresh_token)
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

    def handle(self, provider, owner):
        return self.response(self)


class BlindAuthorizationProvider(AuthorizationProvider):

    def __init__(self, store):
        super(BlindAuthorizationProvider, self).__init__(store)

        self.requests['grant_type']['test'] = Request

    def authorize_client(self, client):
        return True


class BrokenAuthorizationProvider(BlindAuthorizationProvider):

    def authorize_client(self, client):
        raise RuntimeError


class DummyAuthorizationProvider(BlindAuthorizationProvider):

    def authorize_client(self, client):
        raise message.UnauthorizedClient

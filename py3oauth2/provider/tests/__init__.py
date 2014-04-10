# -*- coding: utf-8 -*-

from ..interfaces import (
    IAccessToken,
    IAuthorizationCode,
    IClient,
    IStore,
)


class Owner:

    def __init__(self, id):
        self.id = id


class Client(IClient):

    def __init__(self, id):
        self.id = id

    def get_id(self):
        return self.id


class AccessToken(IAccessToken):

    def __init__(self, owner, client, token, expires_in, scope,
                 refresh_token=None):
        self.owner = owner
        self.client = client
        self.token = token
        self.expires_in = expires_in
        self.scope = scope
        self.refresh_token = refresh_token

    def get_client(self):
        return self.client

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
        self.authorization_codes = dict()

    def get_client(self, client_id):
        return self.clients.get(client_id)

    def persist_access_token(self, token):
        self.access_tokens[token.get_token()] = token

    def discard_access_token(self, token):
        del self.access_tokens[token.get_token()]

    def persist_authorization_code(self, code):
        self.authorization_codes[code.get_code()] = code

    def discard_authorization_code(self, code):
        del self.authorization_codes[code.get_code()]

    def get_authorization_code(self, code):
        return self.authorization_codes.get(code.get_code())

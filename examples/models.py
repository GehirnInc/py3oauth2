# -*- coding: utf-8 -*-

import base64
import os
from datetime import (
    datetime,
    timedelta,
)

from py3oauth2.interfaces import (
    IAccessToken,
    IAuthorizationCode,
    IClient,
    IStore,
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

    def __init__(self, client, owner, scope, expires_in):
        self.client = client
        self.owner = owner
        self.scope = scope
        self.expires_in = expires_in

        self.token = base64.b64encode(os.urandom(16)).decode('utf8')
        self.refresh_token = base64.b64encode(os.urandom(16)).decode('utf8')

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

    def get_expires_at(self):
        return self.issued_at + timedelta(seconds=self.get_expires_in())

    def get_scope(self):
        return self.scope

    def get_refresh_token(self):
        return self.refresh_token


class AuthorizationCode(IAuthorizationCode):

    def __init__(self, client, owner, scope):
        self.client = client
        self.owner = owner
        self.scope = scope

        self.code = base64.b64encode(os.urandom(16)).decode('utf8')
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

    def issue_access_token(self, client, owner, scope):
        tokenobj = AccessToken(client, owner, scope, 3600)
        self.access_tokens[tokenobj.get_token()] = tokenobj
        if tokenobj.get_refresh_token():
            self.refresh_tokens[tokenobj.get_refresh_token()] = tokenobj

        return tokenobj

    def issue_authorization_code(self, client, owner, scope):
        codeobj = AuthorizationCode(client, owner, scope)
        self.authorization_codes[codeobj.get_code()] = codeobj
        return codeobj

    def get_client(self, client_id):
        return self.clients.get(client_id)

    def get_access_token(self, token):
        return self.access_tokens.get(token)

    def get_access_token_by_refresh_token(self, refresh_token):
        return self.refresh_tokens.get(refresh_token)

    def get_authorization_code(self, code):
        return self.authorization_codes.get(code)

    def discard_access_token(self, token):
        del self.access_tokens[token.get_token()]

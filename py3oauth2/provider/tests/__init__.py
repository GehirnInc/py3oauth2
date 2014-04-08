# -*- coding: utf-8 -*-

from ..interfaces import (
    IAccessToken,
    IAuthorizationCode,
    IClient,
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

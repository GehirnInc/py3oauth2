# -*- coding: utf-8 -*-

import enum


class ClientType(enum.Enum):
    PUBLIC = 'public'
    CONFIDENTIAL = 'confidential'


class IClient:

    def get_id(self):
        raise NotImplementedError

    def get_redirect_uri(self):
        raise NotImplementedError

    def get_type(self):
        raise NotImplementedError


class IAccessToken:

    def get_client(self):
        raise NotImplementedError

    def get_owner(self):
        raise NotImplementedError

    def get_token(self):
        raise NotImplementedError

    def get_type(self):
        raise NotImplementedError

    def get_expires_in(self):
        raise NotImplementedError

    def get_expires_at(self):
        raise NotImplementedError

    def get_scope(self):
        raise NotImplementedError

    def get_refresh_token(self):
        raise NotImplementedError


class IAuthorizationCode:

    def get_client(self):
        raise NotImplementedError

    def get_owner(self):
        raise NotImplementedError

    def get_code(self):
        raise NotImplementedError

    def get_scope(self):
        raise NotImplementedError

    def is_active(self):
        raise NotImplementedError

    def deactivate(self):
        raise NotImplementedError


class IStore:

    def issue_access_token(self, client, owner, scope):
        raise NotImplementedError

    def issue_authorization_code(self, client, owner, scope):
        raise NotImplementedError

    def get_client(self, client_id):
        raise NotImplementedError

    def get_access_token(self, token):
        raise NotImplementedError

    def get_access_token_by_refresh_token(self, refresh_token):
        raise NotImplementedError

    def get_authorization_code(self, code):
        raise NotImplementedError

    def discard_access_token(self, token):
        raise NotImplementedError

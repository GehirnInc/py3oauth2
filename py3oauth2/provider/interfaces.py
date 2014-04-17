# -*- coding: utf-8 -*-


class IClient:

    def get_id(self):
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

    def get_scope(self):
        raise NotImplementedError

    def get_refresh_token(self):
        raise NotImplementedError

    def get_issued_at(self):
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

    def is_used(self):
        raise NotImplementedError

    def mark_as_used(self):
        raise NotImplementedError


class IStore:

    def get_client(self, client_id):
        raise NotImplementedError

    def persist_access_token(self, client, owner, token, scope, refresh_token):
        raise NotImplementedError

    def discard_access_token(self, token):
        raise NotImplementedError

    def get_access_token(self, token):
        raise NotImplementedError

    def get_access_token_by_refresh_token(self, refresh_token):
        raise NotImplementedError

    def get_access_token_length(self):
        raise NotImplementedError

    def get_refresh_token_length(self):
        raise NotImplementedError

    def persist_authorization_code(self, client, owner, code, scope):
        raise NotImplementedError

    def get_authorization_code(self, code):
        raise NotImplementedError

    def get_authorization_code_length(self):
        raise NotImplementedError

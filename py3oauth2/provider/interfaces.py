# -*- coding: utf-8 -*-


class IClient:

    def get_id(self):
        raise NotImplementedError


class IAccessToken:

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
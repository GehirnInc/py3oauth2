# -*- coding: utf-8 -*-


class IStore:

    def get_client(self, client_id):
        raise NotImplementedError

    def persist_access_token(self, client, owner, token):
        raise NotImplementedError

    def persist_authorization_code(self, client, owner, code, scope):
        raise NotImplementedError

    def discard_authorization_code(self, client, code):
        raise NotImplementedError

    def persist_refresh_token(self, client, access_token):
        raise NotImplementedError

    def discard_refresh_token(self, client, refresh_token):
        raise NotImplementedError

    def get_authorization_code(self, code):
        raise NotImplementedError

    def get_authorization_code_length(self):
        return 40

    def get_access_token_length(self):
        return 40

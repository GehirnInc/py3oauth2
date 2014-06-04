# -*- coding: utf-8 -*-

from py3oauth2 import message
from py3oauth2.errors import (
    AccessDenied,
    InvalidRequest,
    UnauthorizedClient,
)
from py3oauth2.interfaces import IClient


__all__ = [
    'AuthorizationResponse',
    'AuthorizationRequest',
    'AccessTokenRequest'
]


class AuthorizationResponse(message.Response):
    code = message.Parameter(str, required=True)
    state = message.Parameter(str, required=message.is_state_required)

    def is_redirect(self):
        return True


class AuthorizationRequest(message.Request):
    response = AuthorizationResponse

    response_type = message.Parameter(str, required=True,
                                      default='code', editable=False)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str, recommended=True)

    def answer(self, provider, owner):
        client = provider.store.get_client(self.client_id)
        if not isinstance(client, IClient)\
                or not provider.authorize_client(client):
            raise UnauthorizedClient(self, True)

        redirect_uri = self.redirect_uri or client.get_redirect_uri()
        if not redirect_uri:
            raise InvalidRequest(self, True)
        elif not provider.validate_redirect_uri(client, redirect_uri):
            raise UnauthorizedClient(self, True)

        code = provider.store.issue_authorization_code(
            client, owner, provider.normalize_scope(self.scope))
        return self.response.from_dict(self, {
            'code': code.get_code(),
            'state': self.state,
            'redirect_uri': redirect_uri,
        })


class AccessTokenRequest(message.Request):
    response = message.AccessTokenResponse

    grant_type = message.Parameter(str, required=True,
                                   default='authorization_code',
                                   editable=False)
    code = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    client_id = message.Parameter(str, required=True)

    def answer(self, provider, owner):
        authcode = provider.store.get_authorization_code(self.code)
        if authcode is None or authcode.is_used():
            # NOTES: If an authorization code is used more than once,
            # the authorization server MUST deny the request and SHOULD
            # revoke (when possible) all tokens previously issued
            # based on that authorization code.
            raise AccessDenied(self)

        client = provider.store.get_client(self.client_id)
        if not isinstance(client, IClient)\
                or not provider.authorize_client(client)\
                or client != authcode.get_client():
            raise UnauthorizedClient(self)

        token = provider.store.issue_access_token(authcode.get_client(),
                                                  authcode.get_owner(),
                                                  authcode.get_scope())
        return self.response.from_dict(self, {
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
            'refresh_token': token.get_refresh_token(),
            'scope': ' '.join(token.get_scope()),
        })

# -*- coding: utf-8 -*-

from py3oauth2 import message
from py3oauth2.errors import (
    AccessDenied,
    ErrorException,
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
        if not isinstance(client, IClient):
            raise UnauthorizedClient(self)

        redirect_uri = self.redirect_uri or client.get_redirect_uri()
        if not redirect_uri:
            raise InvalidRequest(self)
        elif not provider.validate_redirect_uri(client, redirect_uri):
            raise UnauthorizedClient(self)

        try:
            code = provider.store.issue_authorization_code(
                client, owner, provider.normalize_scope(self.scope))
        except ErrorException as why:
            why.request = self
            raise

        response = self.response(self, redirect_uri)
        response.update({
            'code': code.get_code(),
            'state': self.state,
        })
        return response


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
        if authcode is None or not authcode.is_active():
            # NOTES: If an authorization code is used more than once,
            # the authorization server MUST deny the request and SHOULD
            # revoke (when possible) all tokens previously issued
            # based on that authorization code.
            raise AccessDenied(self)

        authcode.deactivate()

        client = provider.store.get_client(self.client_id)
        if not isinstance(client, IClient)\
                or not provider.authorize_client(client)\
                or client != authcode.get_client():
            raise UnauthorizedClient(self)

        try:
            token = provider.store.issue_access_token(authcode.get_client(),
                                                      authcode.get_owner(),
                                                      authcode.get_scope())
        except ErrorException as why:
            why.request = self
            raise

        response = self.response(self)
        response.update({
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
            'refresh_token': token.get_refresh_token(),
            'scope': ' '.join(token.get_scope()),
        })
        return response

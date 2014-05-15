# -*- coding: utf-8 -*-

from . import message


def is_state_required(self):
    return hasattr(self.request, 'state') and self.request.state is not None


__all__ = ['AuthorizationResponse', 'AuthorizationErrorResponse',
           'AuthorizationRequest', 'AccessTokenRequest']


class AuthorizationResponse(message.Response):
    code = message.Parameter(str, required=True)
    state = message.Parameter(str, required=is_state_required)

    def is_redirect(self):
        return True


class AuthorizationErrorResponse(message.Response):
    error = message.Parameter(str, required=True)
    error_descritpion = message.Parameter(str)
    error_uri = message.Parameter(str)
    state = message.Parameter(str, required=is_state_required)

    def is_redirect(self):
        return True


class AuthorizationRequest(message.Request):
    response = AuthorizationResponse
    err_response = AuthorizationErrorResponse

    response_type = message.Parameter(str, required=True,
                                      default='code', editable=False)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str, recommended=True)

    def answer(self, provider, owner):
        client = provider.store.get_client(self.client_id)
        if client is None or not provider.authorize_client(client):
            raise message.UnauthorizedClient

        redirect_uri = self.redirect_uri or client.get_redirect_uri()
        if not redirect_uri:
            raise message.InvalidRequet()
        elif not provider.validate_redirect_uri(client, redirect_uri):
            raise message.UnauthorizedClient()

        code = provider.store.persist_authorization_code(
            client, owner, provider.generate_authorization_code(),
            self.scope)

        return self.response.from_dict(self, {
            'code': code.get_code(),
            'state': self.state,
            'redirect_uri': redirect_uri,
        })


class AccessTokenRequest(message.Request):
    response = message.AccessTokenResponse
    err_response = message.ErrorResponse

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
            raise message.AccessDenied()

        client = provider.store.get_client(self.client_id)
        if client is None or not provider.authorize_client(client)\
                or client.get_id() != authcode.get_client().get_id():
            raise message.UnauthorizedClient

        token = provider.store.persist_access_token(
            authcode.get_client(), authcode.get_owner(),
            provider.generate_access_token(), authcode.get_scope(),
            provider.generate_refresh_token())

        return self.response.from_dict(self, {
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
            'refresh_token': token.get_refresh_token(),
            'scope': token.get_scope(),
        })

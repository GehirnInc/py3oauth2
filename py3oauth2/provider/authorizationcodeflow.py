# -*- coding: utf-8 -*-

from . import message


class AuthorizationResponse(message.Response):
    code = message.Parameter(str, required=True)
    scope = message.Parameter(
        str,
        required=lambda self: 'scope' in self.request and self.request.scope)


class AuthorizationErrorResponse(message.Response):
    error = message.Parameter(str, required=True)
    error_descritpion = message.Parameter(str)
    error_uri = message.Parameter(str)
    state = message.Parameter(
        str,
        required=lambda self: 'state' in self.request and self.request.state)


class AuthorizationRequest(message.Request):
    response = AuthorizationResponse
    err_response = AuthorizationErrorResponse

    response_type = message.Parameter(str, required=True)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str)


class AccessTokenRequest(message.Request):
    response = message.AccessTokenResponse
    err_response = message.ErrorResponse

    grant_type = message.Parameter(str, required=True)
    code = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    client_id = message.Parameter(str)

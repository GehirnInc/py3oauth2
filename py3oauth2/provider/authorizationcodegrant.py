# -*- coding: utf-8 -*-

from . import message


def is_state_required(self):
    return hasattr(self.request, 'state') and self.request.state is not None


class AuthorizationResponse(message.Message):
    code = message.Parameter(str, required=True)
    state = message.Parameter(str, required=is_state_required)

    @classmethod
    def from_request(cls, request, code):
        inst = cls()
        inst.code = code.get_code()

        if not hasattr(request, 'state') or request.state is None:
            return inst

        inst.state = request.state
        return inst


class AuthorizationErrorResponse(message.Message):
    error = message.Parameter(str, required=True)
    error_descritpion = message.Parameter(str)
    error_uri = message.Parameter(str)
    state = message.Parameter(str, required=is_state_required)


class AuthorizationRequest(message.Message):
    response = AuthorizationResponse
    err_response = AuthorizationErrorResponse

    response_type = message.Parameter(str, required=True)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str)


class AccessTokenRequest(message.Message):
    response = message.AccessTokenResponse
    err_response = message.ErrorResponse

    grant_type = message.Parameter(str, required=True)
    code = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    client_id = message.Parameter(str)

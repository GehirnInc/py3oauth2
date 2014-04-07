# -*- coding: utf-8 -*-

from . import message


def is_state_required(self):
    return hasattr(self.request, 'state') and self.request.state is not None


class Response(message.Response):

    access_token = message.Parameter(str, required=True)
    token_type = message.Parameter(str, required=True)
    expires_in = message.Parameter(int)
    scope = message.Parameter(str)
    state = message.Parameter(str, is_state_required)

    @classmethod
    def from_request(cls, request, token):
        D = {
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
        }
        if hasattr(request, 'scope') and request.scope != token.get_scope():
            D['scope'] = token.get_scope()

        if hasattr(request, 'state') and request.state is not None:
            D['state'] = request.state

        return cls.from_dict(request, D)


class ErrorResponse(message.Response):

    error = message.Parameter(str, required=True)
    error_descritpion = message.Parameter(str)
    error_uri = message.Parameter(str)
    state = message.Parameter(str, is_state_required)


class Request(message.Request):
    response = Response
    err_response = ErrorResponse

    response_type = message.Parameter(str, required=True)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str, recommended=True)

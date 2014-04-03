# -*- coding: utf-8 -*-

from .message import (
    Message,
    Parameter,
)


def is_state_required(self):
    return hasattr(self.request, 'state') and self.request.state is not None


class Response(Message):

    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int)
    scope = Parameter(str)
    state = Parameter(str, is_state_required)


class ErrorResponse(Message):

    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)
    state = Parameter(str, is_state_required)


class Request(Message):
    response = Response
    err_response = ErrorResponse

    response_type = Parameter(str, required=True)
    client_id = Parameter(str, required=True)
    redirect_uri = Parameter(str)
    scope = Parameter(str)
    state = Parameter(str, recommended=True)

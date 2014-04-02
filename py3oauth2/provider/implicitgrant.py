# -*- coding: utf-8 -*-

from .message import (
    Parameter,
    Response as BaseResponse,
    Request as BaseRequest,
)


class Response(BaseResponse):

    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int)
    scope = Parameter(str)
    state = Parameter(
        str,
        required=lambda self: 'state' in self.request and self.request.state)


class ErrorResponse(BaseResponse):

    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)
    state = Parameter(
        str,
        required=lambda self: 'state' in self.request and self.request.state)


class Request(BaseRequest):
    response = Response
    err_response = ErrorResponse

    response_type = Parameter(str, required=True)
    client_id = Parameter(str, required=True)
    redirect_uri = Parameter(str)
    scope = Parameter(str)
    state = Parameter(str, recommended=True)

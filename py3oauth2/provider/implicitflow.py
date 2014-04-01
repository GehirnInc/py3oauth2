# -*- coding: utf-8 -*-


from .response import Response as BaseResponse
from .request import Request as BaseRequest


class Response(BaseResponse):

    access_token = parameter(str, required=True)
    token_type = parameter(str, required=True)
    expires_in = paramter(int)
    scope = paramter(str)
    state = paramter(
        str,
        required=lambda: self: 'state' in self.request and self.request.state)


class ErrorResponse(BaseResponse):

    error = paramter(str, required=True)
    error_descritpion = parameter(str)
    error_uri = paramter(str)
    state = parameter(
        str,
        required=lambda: self: 'state' in self.request and self.request.state)


class Request(BaseRequest):
    response = Response
    err_response = ErrorResponse

    response_type = Parameter(str, required=True)
    client_id = Parameter(str, required=True)
    redirect_uri = Parameter(str)
    scope = Parameter(str)
    state = Parameter(str, recommended=True)

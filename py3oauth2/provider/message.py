# -*- coding: utf-8 -*-

class Parameter:

    def __init__(self, type, required=False, recommended=False):
        self.type = type
        self.required = required
        self.recommended = recommended


class Request(dict):

    def validate(self):
        raise NotImplementedError

    def to_json(self):
        pass


class RefreshTokenRequest(Request):

    grant_type = Parameter(str, required=True)
    refresh_token = Parameter(str, required=True)
    scope = Parameter(str)


class Response(dict):

    def validate(self):
        raise NotImplementedError

    def to_json(self):
        pass


class AccessTokenResponse(Response):
    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int, recommended=True)
    refresh_token = Parameter(str)
    scope = Parameter(str)


class ErrorResponse(Response):

    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)

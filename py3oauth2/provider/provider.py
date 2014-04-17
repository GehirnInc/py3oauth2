# -*- coding: utf-8 -*-

from . import (
    authorizationcodegrant,
    implicitgrant,
    refreshtokengrant,
    utils,
)
from .exceptions import (
    ErrorResponse,
    UnknownRequest,
    ValidationError,
)


__all__ = ['AuthorizationProvider']


class AuthorizationProvider:
    requests = {
        'grant_type': {
            'refresh_token': refreshtokengrant.Request,
            'authorization_code': authorizationcodegrant.AccessTokenRequest
        },
        'response_type': {
            'code': authorizationcodegrant.AuthorizationRequest,
            'token': implicitgrant.Request,
        },
    }

    def __init__(self, store):
        self.store = store

    def authorize_client(self, client):
        raise NotImplementedError

    def _generate_random_string(self, length):
        return utils.generate_random_string(
            length,
            utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
        )

    def generate_authorization_code(self):
        return self._generate_random_string(
            self.store.get_authorization_code_length())

    def generate_access_token(self):
        return self._generate_random_string(
            self.store.get_access_token_length())

    def generate_refresh_token(self):
        return self._generate_random_string(
            self.store.get_refresh_token_length())

    def detect_request_class(self, request):
        if 'grant_type' in request:
            return self.requests['grant_type'].get(request['grant_type'])
        elif 'response_type' in request:
            return self.requests['response_type'].get(request['response_type'])

        return None

    def decode_request(self, request_dict):
        request_class = self.detect_request_class(request_dict)
        if request_class is None:
            raise UnknownRequest()

        try:
            request = request_class.from_dict(request_dict)
            request.validate()
        except ValidationError as why:
            resp = request_class.err_response(request)
            resp.error = 'invalid_request'
            raise ErrorResponse(resp) from why
        else:
            return request

    def handle_request(self, request, owner=None):
        try:
            resp = request.answer(self, owner)
            resp.validate()
        except BaseException as why:
            resp = request.err_response(request)
            resp.error = 'server_error'
            raise ErrorResponse(resp) from why
        else:
            return resp

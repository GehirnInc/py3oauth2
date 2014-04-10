# -*- coding: utf-8 -*-

from . import (
    authorizationcodegrant,
    implicitgrant,
    refreshtokengrant,
    utils,
)
from .exceptions import ValidationError


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

    def generate_authorization_code(self):
        return utils.generate_random_string(
            self.store.get_authorization_code_length(),
            utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
        )

    def generate_access_token(self):
        return utils.generate_random_string(
            self.store.get_access_token_length(),
            utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
        )

    def _detect_request_class(self, request):
        if 'grant_type' in request:
            return self.requests['grant_type'].get(request['grant_type'])
        elif 'response_type' in request:
            return self.requests['response_type'].get(request['response_type'])

        return None

    def handle_request(self, request_dict, owner=None):
        request_class = self._detect_request_class(request_dict)
        if request_class is None:
            raise ValueError('Request class not found')

        request = request_class.from_dict(request_dict)
        try:
            request.validate()
        except ValidationError:
            resp = request_class.err_response(request)
            resp.error = 'invalid_request'
            return resp
        else:
            try:
                resp = request.answer(self, owner)
                resp.validate()
            except:
                resp = request_class.err_response(request)
                resp.error = 'server_error'
                return resp
            else:
                return resp

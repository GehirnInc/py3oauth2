# -*- coding: utf-8 -*-

import collections
from datetime import datetime

from py3oauth2 import (
    authorizationcodegrant,
    implicitgrant,
    message,
    refreshtokengrant,
    utils,
)
from py3oauth2.errors import (
    AccessDenied,
    ErrorException,
    InvalidRequest,
    ServerError,
    UnsupportedGrantType,
    UnsupportedResponseType,
)
from py3oauth2.exceptions import ValidationError
from py3oauth2.interfaces import ClientType


__all__ = ['AuthorizationProvider', 'ResourceProvider']


class AuthorizationProvider:
    authz_handlers = {
        ('token', ): implicitgrant.Request,
        ('code', ): authorizationcodegrant.AuthorizationRequest,
    }

    token_handlers = {
        'refresh_token': refreshtokengrant.Request,
        'authorization_code': authorizationcodegrant.AccessTokenRequest,
    }

    def __init__(self, store, **kwargs):
        self.store = store

    @staticmethod
    def normalize_scope(scope):
        if isinstance(scope, str):
            return set(scope.split())

        return set()

    @staticmethod
    def normalize_response_type(response_type):
        assert isinstance(response_type, collections.Iterable)

        response_type = sorted(response_type)
        response_type = tuple(type for i, type in enumerate(response_type)
                              if response_type not in response_type[:i])
        return response_type

    @classmethod
    def add_authorization_handler(cls, response_type, handler):
        assert isinstance(response_type, tuple)
        assert issubclass(handler, message.Request)

        cls.authz_handlers[cls.normalize_response_type(response_type)]\
            = handler

    @classmethod
    def add_token_handler(cls, grant_type, handler):
        assert isinstance(grant_type, str)
        assert issubclass(handler, message.Request)

        cls.token_handlers[grant_type] = handler

    def authorize_client(self, client):
        raise NotImplementedError

    def validate_redirect_uri(self, client, redirect_uri):
        if not client.get_redirect_uri():
            return client.get_type() is ClientType.CONFIDENTIAL

        authorized_url = utils.normalize_url(client.get_redirect_uri())
        if '?' in authorized_url:
            authorized_url = authorized_url.split('?', 1)[0]

        redirect_uri = utils.normalize_url(redirect_uri)
        if '?' in redirect_uri:
            redirect_uri = authorized_url.split('?', 1)[0]

        return authorized_url == redirect_uri

    def _decode_request(self, registry, key, request_dict, err_kind, state):
        assert isinstance(registry, dict)
        assert isinstance(request_dict, dict)
        assert issubclass(err_kind, ErrorException)

        try:
            handler = registry[key]
        except KeyError as why:
            raise err_kind(request_dict) from why

        request = handler.from_dict(request_dict)
        try:
            request.validate()
            return request
        except BaseException as why:
            if isinstance(why, ValidationError):
                raise InvalidRequest(request) from why

            raise ServerError(request) from why

    def decode_authorize_request(self, request_dict):
        state = request_dict.get('state')

        response_type = request_dict.get('response_type')
        if not isinstance(response_type, str):
            raise UnsupportedResponseType(request_dict)
        response_type = self.normalize_response_type(response_type.split())

        return self._decode_request(self.authz_handlers,
                                    response_type,
                                    request_dict,
                                    UnsupportedResponseType,
                                    state)

    def decode_token_request(self, request_dict):
        state = request_dict.get('state')

        grant_type = request_dict.get('grant_type')
        return self._decode_request(self.token_handlers,
                                    grant_type,
                                    request_dict,
                                    UnsupportedGrantType,
                                    state)

    def handle_request(self, request, owner=None):
        try:
            resp = request.answer(self, owner)
            resp.validate()

            return resp
        except BaseException as why:
            if isinstance(why, ErrorException):
                raise

            raise ServerError(request) from why


class ResourceProvider:

    def __init__(self, store):
        self.store = store

    def get_access_token(self):
        raise NotImplementedError

    def validate_access_token(self, token, token_type):
        if token.get_type() != token_type:
            return False

        return datetime.utcnow() <= token.get_expires_at()

    def authorize(self, required_scope):
        assert isinstance(required_scope, set)
        try:
            token, token_type = self.get_access_token()
            tokenobj = self.store.get_access_token(token)
            if tokenobj is None or\
                    not self.validate_access_token(tokenobj, token_type):
                raise AccessDenied()

            if not required_scope.issubset(tokenobj.get_scope()):
                raise AccessDenied()
        except AccessDenied:
            raise
        else:
            return tokenobj

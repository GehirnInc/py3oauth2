# -*- coding: utf-8 -*-

from py3oauth2.exceptions import OAuthException
from py3oauth2.message import (
    is_state_required,
    MessageMeta,
    Parameter,
    Request,
    Response,
)


class ErrorResponse(Response):
    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)
    state = Parameter(str, required=is_state_required)

    def __init__(self, request, is_redirect):
        super(ErrorResponse, self).__init__(request)
        self.redirect = is_redirect

    def is_redirect(self):
        return self.redirect

    def get_content_type(self):
        return 'text/json;charset=utf8'

    def get_response_body(self):
        return self.to_json()

    @classmethod
    def from_dict(cls, request, is_redirect, D):
        inst = cls(request, is_redirect)
        inst._from_dict(D)
        return inst


class ErrorException(OAuthException):

    def __init__(self, request, is_redirect=False):
        self.request = request
        self.is_redirect = is_redirect

    @property
    def response(self):
        if isinstance(self.request, Request):
            state =\
                hasattr(self.request, 'state') and self.request.state or None
        else:
            state = self.request.get('state')

        return self.klass.from_dict(self.request, self.is_redirect, {
            'state': state,
        })


def make_error(name, error):
    return type('{name}Exception'.format(name=name), (ErrorException, ), {
        'klass': MessageMeta(name, (ErrorResponse, ), {
            'error': Parameter(str, required=True, default=error,
                               editable=False),
        })
    })

AccessDenied = make_error('AccessDenied', 'access_denied')
UnauthorizedClient = make_error('UnauthorizedClient', 'unauthorized_client')
ServerError = make_error('ServerError', 'server_error')
InvalidRequest = make_error('InvalidRequest', 'invalid_request')
UnsupportedGrantType = make_error('UnsupportedGrantType',
                                  'unsupported_grant_type')
UnsupportedResponseType = make_error('UnsupportedResponseType',
                                     'unsupported_response_type')
InvalidScope = make_error('InvalidScope', 'invalid_scope')

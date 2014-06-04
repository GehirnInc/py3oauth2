# -*- coding: utf-8 -*-

from py3oauth2 import message
from py3oauth2.errors import (
    InvalidRequest,
    UnauthorizedClient,
)
from py3oauth2.interfaces import IClient

__all__ = ['Response', 'Request']


class Response(message.Response):
    access_token = message.Parameter(str, required=True)
    token_type = message.Parameter(str, required=True)
    expires_in = message.Parameter(int)
    scope = message.Parameter(str)
    state = message.Parameter(str, message.is_state_required)

    def is_redirect(self):
        return True


class Request(message.Request):
    response = Response

    response_type = message.Parameter(str, required=True,
                                      default='token', editable=False)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str, recommended=True)

    def answer(self, provider, owner):
        client = provider.store.get_client(self.client_id)
        if not isinstance(client, IClient)\
                or not provider.authorize_client(client):
            raise UnauthorizedClient

        redirect_uri = self.redirect_uri if self.redirect_uri\
            else client.get_redirect_uri()
        if not redirect_uri:
            raise InvalidRequest()
        elif not provider.validate_redirect_uri(client, redirect_uri):
            raise UnauthorizedClient()

        token = provider.store.issue_access_token(
            client, owner, provider.normalize_scope(self.scope))

        response = self.response.from_dict(self, {
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
            'scope': ' '.join(token.get_scope()),
            'state': self.state,
        })
        response.redirect_uri = redirect_uri

        return response

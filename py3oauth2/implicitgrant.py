# -*- coding: utf-8 -*-

from py3oauth2 import message
from py3oauth2.errors import (
    ErrorException,
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
        if not isinstance(client, IClient):
            raise UnauthorizedClient(self)

        redirect_uri = self.redirect_uri or client.get_redirect_uri()
        if not redirect_uri:
            raise InvalidRequest(self)
        elif not provider.validate_redirect_uri(client, redirect_uri):
            raise UnauthorizedClient(self)

        try:
            token = provider.store.issue_access_token(
                client, owner, provider.normalize_scope(self.scope))
        except ErrorException as why:
            why.request = self
            why.redirect_uri = redirect_uri
            raise

        response = self.response(self, redirect_uri)
        response.update({
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
            'scope': ' '.join(token.get_scope()),
            'state': self.state,
        })
        return response

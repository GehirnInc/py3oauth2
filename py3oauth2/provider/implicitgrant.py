# -*- coding: utf-8 -*-

from . import message

__all__ = ['Response', 'ErrorResponse', 'Request']


def is_state_required(self):
    return hasattr(self.request, 'state') and self.request.state is not None


class Response(message.Response):
    access_token = message.Parameter(str, required=True)
    token_type = message.Parameter(str, required=True)
    expires_in = message.Parameter(int)
    scope = message.Parameter(str)
    state = message.Parameter(str, is_state_required)

    def is_redirect(self):
        return True


class ErrorResponse(message.Response):

    error = message.Parameter(str, required=True)
    error_descritpion = message.Parameter(str)
    error_uri = message.Parameter(str)
    state = message.Parameter(str, is_state_required)


class Request(message.Request):
    response = Response
    err_response = ErrorResponse

    response_type = message.Parameter(str, required=True,
                                      default='token', editable=False)
    client_id = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str)
    scope = message.Parameter(str)
    state = message.Parameter(str, recommended=True)

    def answer(self, provider, owner):
        try:
            try:
                client = provider.store.get_client(self.client_id)
                if client is None or not provider.authorize_client(client):
                    raise message.UnauthorizedClient
                client = client

                redirect_uri = self.redirect_uri if self.redirect_uri\
                    else client.get_redirect_uri()
                if not redirect_uri:
                    raise message.InvalidRequet()
                elif not provider.validate_redirect_uri(client, redirect_uri):
                    raise message.UnauthorizedClient()

                token = provider.store.persist_access_token(
                    client, owner, provider.generate_access_token(),
                    self.scope, None)
            except message.RequestError:
                raise
            except:
                raise message.ServerError()
        except message.RequestError as why:
            resp = self.err_response(self)
            resp.error = why.kind
            resp.state = self.state
            resp.redirect_uri = self.redirect_uri
            return resp
        else:
            response = self.response.from_dict(self, {
                'access_token': token.get_token(),
                'token_type': token.get_type(),
                'expires_in': token.get_expires_in(),
                'scope': token.get_scope(),
                'state': self.state,
            })
            response.redirect_uri = redirect_uri
            return response

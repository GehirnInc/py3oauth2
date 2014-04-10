# -*- coding: utf-8 -*-

from .message import (
    AccessDenied,
    AccessTokenResponse,
    ErrorResponse,
    Parameter,
    Request,
    RequestError,
    ServerError,
)


__all__ = ['RefreshTokenRequest']


class RefreshTokenRequest(Request):
    response = AccessTokenResponse
    err_response = ErrorResponse

    grant_type = Parameter(str, required=True,
                           default='refresh_token', editable=False)
    refresh_token = Parameter(str, required=True)
    scope = Parameter(str)

    def answer(self, provider, owner):
        try:
            try:
                previous = provider.store.get_access_token_by_refresh_token(
                    self.refresh_token
                )
                if previous is None:
                    raise AccessDenied
                provider.store.discard_access_token(previous)

                provider.authorize_client(previous.get_client())

                if self.scope:
                    if previous.get_scope() is None:
                        raise AccessDenied

                    prescopes = set(previous.get_scope().split())
                    reqscopes = set(self.scope.split())
                    if not reqscopes.issubset(prescopes):
                        raise AccessDenied

                token = provider.store.persist_access_token(
                    previous.get_client(), previous.get_owner(),
                    provider.generate_access_token(),
                    self.scope or previous.get_scope(),
                    provider.generate_refresh_token())
            except RequestError:
                raise
            except:
                raise ServerError()
        except RequestError as why:
            resp = self.err_response(self)
            resp.error = why.kind
            return resp
        else:
            return self.response.from_dict(self, {
                'access_token': token.get_token(),
                'token_type': token.get_type(),
                'expires_in': token.get_expires_in(),
                'refresh_token': token.get_refresh_token(),
                'scope': token.get_scope(),
            })

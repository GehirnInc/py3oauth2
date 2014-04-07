# -*- coding: utf-8 -*-

from . import utils
from .exceptions import DenyAuthentication


class AuthorizationProvider:

    def __init__(self, store):
        self.store = store

    def validate_client(self, client):
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

    def handle_request(self, request, owner=None):
        if hasattr(request, 'response_type'):
            if request.response_type == 'code':
                # authorization code grant
                return self._handle_authcode_code(request, owner)
            elif request.response_type == 'token':
                # implicit grant
                return self._handle_implicit_access_token(request, owner)
            else:
                resp = request.err_response(request)
                resp.error = 'unsupported_response_type'
                return resp
        elif hasattr(request, 'grant_type'):
            if request.grant_type == 'authorization_code':
                return self._handle_authcode_token(request)
            elif request.grant_type == 'refresh_token':
                return self._handle_refresh_token(request)
            else:
                resp = request.err_response(request)
                resp.error = 'unsupported_grant_type'
                return resp
        else:
            resp = request.err_response(request)
            resp.error = 'invalid_request'
            return resp

    def _handle_authcode_code(self, request, owner):
        try:
            client = self.store.get_client(request.client_id)
            if client is None or not self.validate_client(client):
                raise ValueError()

            code = self.store.persist_authorization_code(
                client, owner,
                self.generate_authorization_code(), request.scope)
        except ValueError:
            resp = request.err_response(request)
            resp.error = 'unauthorized_client'
            return resp
        except:
            resp = request.err_response(request)
            resp.error = 'server_error'
            return resp
        else:
            return request.response.from_request(request, code)

    def _handle_authcode_token(self, request):
        try:
            authcode = self.store.get_authorization_code(request.code)
            if authcode.is_used:
                raise ValueError()

            try:
                client = self.store.get_client(request.client_id)
                if not self.validate_client(client)\
                        or client.get_id() != authcode.get_client().get_id():
                    raise ValueError()
            except ValueError:
                resp = request.err_response(request)
                resp.error = 'unauthorized_client'
                return resp

            token = self.store.persist_access_token(
                authcode.get_client(), authcode.get_owner(),
                self.generate_access_token(), authcode.get_scope())
        except ValueError:
            resp = request.err_response(request)
            resp.error = 'access_denied'
            return resp
        else:
            return request.response.from_request(request, token)

    def _handle_implicit_access_token(self, request, owner):
        try:
            client = self.store.get_client(request.client_id)
            if not self.validate_client(client):
                raise ValueError()

            token = self.store.persist_access_token(
                client, owner, self.generate_access_token(), request.scope)
        except ValueError:
            resp = request.err_response(request)
            resp.error = 'unauthorized_client'
            return resp
        except:
            resp = request.err_response(request)
            resp.error = 'server_error'
            return resp
        else:
            return request.response.from_request(request, token)

    def _handle_refresh_token(self, request):
        try:
            previous = self.store.from_refresh_token(request.refresh_token)
            self.store.discard_access_token(previous)
            token = self.store.persist_access_token(
                previous.get_client(), previous.get_owner(),
                self.generate_access_token())
        except ValueError:
            resp = request.err_response(request)
            resp.error = 'access_denied'
            return resp
        except:
            resp = request.err_response(request)
            resp.error = 'server_error'
            return resp
        else:
            return request.response.from_request(request, token)

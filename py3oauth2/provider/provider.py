# -*- coding: utf-8 -*-

from . import utils
from .exceptions import DenyAuthentication


class AuthorizationProvider:

    def __init__(self, store):
        self.store = store

    def generate_authorization_code(self):
        return utils.generate_random_string(
            self.store.get_authorization_code_length(),
            utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
        )

    def issue_authorization_code(self, owner, request):
        try:
            client = self.store.get_client(request.client_id)
            if client is None:
                raise ValueError('get_client() returned None')
        except ValueError:
            resp = request.err_response(request)
            resp.error = 'unauthorized_client'
            return resp
        except:
            resp = request.err_response(request)
            resp.error = 'server_error'
            return resp
        else:
            if not hasattr(request, 'response_type')\
                    or request.response_type is None:
                resp = request.err_response(request)
                resp.error = 'invalid_request'
                return resp
            elif request.response_type != 'code':
                resp = request.err_response(request)
                resp.error = 'unsupported_response_type'
                return resp

            code = self.generate_authorization_code()
            try:
                codeobj = self.store.persist_authorization_code(
                    client, owner, code, request.scope
                )
            except DenyAuthentication:
                resp = request.err_response(request)
                resp.error = 'access_denied'
                return resp
            else:
                return request.response.from_request(request, codeobj)

    def generate_access_token(self):
        return utils.generate_random_string(
            self.store.get_access_token_length(),
            utils.RSFlag.LOWER | utils.RSFlag.UPPER | utils.RSFlag.DIGITS
        )

    def issue_access_token(self, owner, request):
        try:
            client = self.store.get_client(request.client_id)
            if client is None:
                raise ValueError('get_client() returned None')
        except ValueError:
            resp = request.err_response(request)
            resp.error = 'unauthorized_client'
            return resp
        except:
            resp = request.err_response(request)
            resp.error = 'server_error'
            return resp
        else:
            if 'grant_type' in request:
                try:
                    if request.grant_type == 'authorization_code':
                        # authorization code grant
                        self.store.discard_authorization_code(client,
                                                              request.code)
                    elif request.grant_type == 'refresh_token':
                        # refresh token
                        self.store.discard_refresh_token(client,
                                                         request.refresh_token)
                    else:
                        resp = request.err_response(request)
                        resp.error = 'unsupported_grant_type'
                        return resp
                except AttributeError:
                    err = request.err_response(request)
                    err.error = 'invalid_request'
                    return err
                except ValueError:
                    err = request.err_response(request)
                    err.error = 'access_denied'
                    return err
            elif 'response' in request:
                # implicit grant
                if request.response != 'token':
                    resp = request.err_response(request)
                    resp.error = 'unsupported_response'
                    return resp
            else:
                resp = request.err_response(request)
                resp.error = 'invalid_request'
                return

            token = self.generate_access_token()
            expires_in = client.get_access_token_expires_in(owner)
            try:
                tokenobj = self.store.persist_access_token(
                    client, owner, token, expires_in)
            except DenyAuthentication:
                resp = request.err_response(request)
                resp.error = 'access_denied'
                return resp
            else:
                return request.response.from_request(request, tokenobj)

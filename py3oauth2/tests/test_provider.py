# -*- coding: utf-8 -*-

import contextlib
import uuid

from py3oauth2.exceptions import (
    ErrorResponse,
)
from py3oauth2.interfaces import ClientType
from py3oauth2.tests import (
    Store,
    mock,
    TestBase,
)


class AuthorizationProviderTest(TestBase):

    def setUp(self):
        self.store = Store()

    @property
    def target(self):
        from py3oauth2.provider import AuthorizationProvider
        return AuthorizationProvider

    def make_target(self, store):
        return self.target(store)

    def test_constructor(self):
        inst = self.make_target(self.store)
        self.assertIs(inst.store, self.store)

    def test_add_authorization_handler(self):
        from py3oauth2.message import Request
        inst = self.make_target(self.store)
        inst.add_authorization_handler(
            ('id_token', 'code', 'token'),
            Request)

        self.assertIn(('code', 'id_token', 'token'), inst.authz_handlers)
        self.assertIs(
            inst.authz_handlers[('code', 'id_token', 'token')],
            Request)

    def test_add_token_handler(self):
        from py3oauth2.message import Request
        inst = self.make_target(self.store)
        inst.add_token_handler('refresh_token', Request)

        self.assertIn('refresh_token', inst.token_handlers)
        self.assertIs(inst.token_handlers['refresh_token'], Request)

    def test_authorize_client(self):
        inst = self.make_target(self.store)
        with self.assertRaises(NotImplementedError):
            inst.authorize_client(object())

    def test_validate_redirect_uri_confidential_registered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.CONFIDENTIAL)

        inst = self.make_target(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(client, 'https://example.com/cb'))

    def test_validate_redirect_uri_confidential_unregistered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.CONFIDENTIAL)

        inst = self.make_target(self.store)
        self.assertFalse(
            inst.validate_redirect_uri(client, 'https://cb.example.com/'))

    def test_validate_redirect_uri_confidential_empty(self):
        client = self.make_client(
            redirect_uri='',
            type=ClientType.CONFIDENTIAL)

        inst = self.make_target(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(client, 'https://example.com/cb'))

    def test_validate_redirect_uri_public_registered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.PUBLIC)

        inst = self.make_target(self.store)
        self.assertTrue(
            inst.validate_redirect_uri(client, 'https://example.com/cb'))

    def test_validate_redirect_uri_public_unregistered(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb',
            type=ClientType.PUBLIC)

        inst = self.make_target(self.store)
        self.assertFalse(
            inst.validate_redirect_uri(client, 'https://cb.example.com/'))

    def test_validate_redirect_uri_contains_query(self):
        client = self.make_client(
            redirect_uri='https://example.com/cb?foo=bar',
            type=ClientType.PUBLIC)

        inst = self.make_target(self.store)
        self.assertTrue(inst.validate_redirect_uri(
            client, 'https://example.com/cb?bar=baz'
        ))

    def test_decode_authorize_request(self):
        client = self.make_client()

        inst = self.make_target(self.store)
        resp = inst.decode_authorize_request({
            'response_type': 'code',
            'state': 'statestring',
            'client_id': client.id,
        })

        self.assertIsInstance(resp, inst.authz_handlers[('code', )])

    def test_decode_authorize_request_unsupported_missing(self):
        # NOTES: missing `response_type`
        client = self.make_client()

        state = str(uuid.uuid4())
        inst = self.make_target(self.store)
        try:
            inst.decode_authorize_request({
                'state': state,
                'client_id': client.id,
            })
        except ErrorResponse as why:
            resp = why.response
            self.assertEqual(resp.error, 'unsupported_response_type')
            self.assertEqual(resp.state, state)
        else:
            self.fail()

    def test_decode_token_request(self):
        client = self.make_client()

        inst = self.make_target(self.store)
        ret = inst.decode_token_request({
            'grant_type': 'authorization_code',
            'client_id': client.id,
            'code': 'authorizationcode',
        })

        self.assertIsInstance(ret, inst.token_handlers['authorization_code'])

    def test_decode_request_unsupported(self):
        inst = self.make_target(self.store)

        with contextlib.ExitStack() as stack:
            response = object()
            err_response =\
                stack.enter_context(mock.patch.object(inst, '_err_response',
                                                      return_value=response))

            try:
                request_dict = dict()
                inst._decode_request({}, object(), request_dict,
                                     'somerror', 'statestring')
            except ErrorResponse as why:
                err_response.assert_called_once_with(request_dict,
                                                     'somerror',
                                                     'statestring')
                self.assertIs(why.response, response)
            else:
                self.fail()

    def test_decode_request_validation_error(self):
        from py3oauth2.message import ValidationError

        inst = self.make_target(self.store)
        with contextlib.ExitStack() as stack:
            response = object()
            err_response =\
                stack.enter_context(mock.patch.object(inst, '_err_response',
                                                      return_value=response))
            request = mock.Mock()
            request.validate.side_effect = ValidationError

            handler = mock.Mock()
            handler.from_dict.return_value = request

            try:
                inst._decode_request({'key': handler}, 'key', {},
                                     'somerror', 'statestring')
            except ErrorResponse as why:
                err_response.assert_called_once_with(request,
                                                     'invalid_request',
                                                     'statestring')
                self.assertIs(why.response, response)
            else:
                self.fail()

    def test_decode_request_server_error(self):
        # NOTES: for example, message parameter's required method
        #        raises exception

        inst = self.make_target(self.store)
        with contextlib.ExitStack() as stack:
            response = object()
            err_response =\
                stack.enter_context(mock.patch.object(inst, '_err_response',
                                                      return_value=response))
            request = mock.Mock()
            request.validate.side_effect = Exception()

            handler = mock.Mock()
            handler.from_dict.return_value = request

            try:
                inst._decode_request({'key': handler}, 'key', {},
                                     'somerror', 'statestring')
            except ErrorResponse as why:
                err_response.assert_called_once_with(request,
                                                     'server_error',
                                                     'statestring')
                self.assertIs(why.response, response)
            else:
                self.fail()

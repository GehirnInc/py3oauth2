# -*- coding: utf-8 -*-

import unittest
import uuid

try:
    from unittest import mock
except ImportError:
    import mock

from examples.models import (
    Client,
    Owner,
    Store,
)

from py3oauth2 import message
from py3oauth2.errors import make_error
from py3oauth2.interfaces import ClientType
from py3oauth2.provider import (
    AuthorizationProvider,
    ResourceProvider,
)


__all__ = ['mock']


DummyError = make_error('DummyError', 'dummy_error')


class Response(message.Response):
    param = message.Parameter(str, required=True)


class Request(message.Request):
    response = Response

    grant_type = message.Parameter(str, required=True,
                                   default='test', editable=False)
    response_type = message.Parameter(str)
    response_mode = message.Parameter(str)

    def handle(self, provider, owner):
        return self.response(self)


class BlindAuthorizationProvider(AuthorizationProvider):

    def __init__(self, store):
        super(BlindAuthorizationProvider, self).__init__(store)

        self.add_token_handler('test', Request)

    def authorize_client(self, client):
        return True


class BrokenAuthorizationProvider(BlindAuthorizationProvider):

    def authorize_client(self, client):
        raise RuntimeError


class DummyAuthorizationProvider(BlindAuthorizationProvider):

    def authorize_client(self, client):
        raise message.UnauthorizedClient


class DummyResourceProvider(ResourceProvider):

    def __init__(self, store, token, token_type):
        super(DummyResourceProvider, self).__init__(store)
        self.token = token
        self.token_type = token_type

    def get_access_token(self):
        return (self.token, self.token_type)


class TestBase(unittest.TestCase):

    def setUp(self):
        self.store = Store()
        self.owner = Owner(str(uuid.uuid4()))

    def make_client(self, id=lambda: str(uuid.uuid4()),
                    redirect_uri='https://example.com/cb',
                    type=ClientType.CONFIDENTIAL):
        if callable(id):
            id = id()

        client = Client(id, redirect_uri, type)
        self.store.persist_client(client)
        return client

    def make_authcode(self, client, owner, scope='view'):
        return self.store.issue_authorization_code(
            client, owner, AuthorizationProvider.normalize_scope(scope))

    def make_owner(self):
        return Owner(str(uuid.uuid4()))

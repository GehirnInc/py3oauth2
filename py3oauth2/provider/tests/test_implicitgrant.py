# -*- coding: utf-8 -*-

import random
import string
import uuid
import unittest

from . import (
    Client,
    BlindAuthorizationProvider,
    BrokenAuthorizationProvider,
    DummyAuthorizationProvider,
    Owner,
    Store,
)
from ..implicitgrant import (
    Request,
)


class TestRequest(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        self.client = Client(str(uuid.uuid4()))
        self.store.persist_client(self.client)

        self.owner = Owner(str(uuid.uuid4()))

    def test_answer_unauthorized_client_1(self):
        provider = BlindAuthorizationProvider(self.store)

        req = Request.from_dict({
            'response_type': 'token',
            'client_id': 'unknown_client_id',
        })
        resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_unauthorized_client_2(self):
        provider = DummyAuthorizationProvider(self.store)

        req = Request.from_dict({
            'response_type': 'token',
            'client_id': self.client.id,
        })
        resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'unauthorized_client')

    def test_answer_server_error(self):
        provider = BrokenAuthorizationProvider(self.store)

        req = Request.from_dict({
            'response_type': 'token',
            'client_id': self.client.id,
        })
        resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.err_response)
        self.assertEqual(resp.error, 'server_error')

    def test_answer(self):
        provider = BlindAuthorizationProvider(self.store)
        pool = string.ascii_letters + string.digits

        req = Request.from_dict({
            'response_type': 'token',
            'client_id': self.client.id,
            'state': ''.join(random.choice(pool) for _ in range(40)),
        })
        resp = req.answer(provider, self.owner)
        resp.validate()

        self.assertIsInstance(resp, req.response)

        token = self.store.get_access_token(resp.access_token)
        self.assertIsNotNone(token)
        self.assertEqual(len(token.get_token()), 40)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.expires_in, token.get_expires_in())
        self.assertEqual(resp.scope, token.get_scope())
        self.assertEqual(resp.state, req.state)

# -*- coding: utf-8 -*-

import unittest


class InterfaceTest(unittest.TestCase):

    def test_IClient(self):
        from py3oauth2.interfaces import IClient

        inst = IClient()
        for name in ('get_id', 'get_redirect_uri', 'get_type'):
            with self.assertRaises(NotImplementedError):
                getattr(inst, name)()

    def test_IAccessToken(self):
        from py3oauth2.interfaces import IAccessToken

        inst = IAccessToken()
        for name in (
            'get_client',
            'get_owner',
            'get_token',
            'get_type',
            'get_expires_in',
            'get_expires_at',
            'get_scope',
            'get_refresh_token'
        ):
            with self.assertRaises(NotImplementedError):
                getattr(inst, name)()

    def test_IAuthorizationCode(self):
        from py3oauth2.interfaces import IAuthorizationCode

        inst = IAuthorizationCode()
        for name in (
            'get_client',
            'get_owner',
            'get_code',
            'get_scope',
            'is_used',
            'mark_as_used',
        ):
            with self.assertRaises(NotImplementedError):
                getattr(inst, name)()

    def test_IStore(self):
        from py3oauth2.interfaces import IStore

        inst = IStore()
        for name in (
            'get_client',
            'get_access_token',
            'get_access_token_by_refresh_token',
            'get_authorization_code',
            'discard_access_token'
        ):
            with self.assertRaises(NotImplementedError):
                getattr(inst, name)(object())

        for name in ('issue_access_token', 'issue_authorization_code'):
            with self.assertRaises(NotImplementedError):
                getattr(inst, name)(object(), object(), object())

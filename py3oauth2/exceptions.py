# -*- coding: utf-8 -*-

OAuthException = type('OAuthException', (Exception, ), {})
ValidationError = type('ValidationError', (OAuthException, ), {})

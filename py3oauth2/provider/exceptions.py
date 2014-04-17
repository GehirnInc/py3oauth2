# -*- coding: utf-8 -*-


AccessDenied = type('AccessDenied', (Exception, ), {})


DenyAuthentication = type('DenyAuthentication', (Exception, ), {})


UnknownRequest = type('UnknownRequest', (ValueError, ), {})


ValidationError = type('ValidationError', (ValueError, ), {})


class ErrorResponse(Exception):

    def __init__(self, response):
        self.response = response

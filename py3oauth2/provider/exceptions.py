# -*- coding: utf-8 -*-


DenyAuthentication = type('DenyAuthentication', (Exception, ), {})


ValidationError = type('ValidationError', (ValueError, ), {})

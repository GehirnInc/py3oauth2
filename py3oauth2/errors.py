# -*- coding: utf-8 -*-


from py3oauth2.message import Parameter


class RequestErrorMeta(type):

    def __new__(cls, name, bases, namespace):
        if not isinstance(bases, tuple):
            bases = (bases, )

        if any(base.__name__ == 'RequestError' for base in bases):
            if 'kind' not in namespace:
                raise AttributeError(
                    'Subclasses of RequestError must have a property `kind`')
            elif not isinstance(namespace['kind'], Parameter):
                raise AttributeError(
                    '`kind` must be a instance of provider.message.Parameter')

            namespace['kind'] = namespace['kind'].new('kind')

        return super(RequestErrorMeta, cls).__new__(cls, name, bases,
                                                    namespace)

RequestError = RequestErrorMeta('RequestError', (ValueError, ), {})


class AccessDenied(RequestError):
    kind = Parameter(str, default='access_denied', editable=False)


class UnauthorizedClient(RequestError):
    kind = Parameter(str, default='unauthorized_client', editable=False)


class ServerError(RequestError):
    kind = Parameter(str, default='server_error', editable=False)


class InvalidRequest(RequestError):
    kind = Parameter(str, default='invalid_request', editable=False)

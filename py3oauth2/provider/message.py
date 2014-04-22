# -*- coding: utf-8 -*-

import json
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    urlunparse,
)

from .exceptions import ValidationError


class Parameter:

    def __init__(self, type, required=False, recommended=False,
                 default=None, editable=True):
        self.type = type
        self.required = required
        self.recommended = recommended
        self.default = default
        self.editable = editable

        self._check_type(self, 'value of argument default', self.default)

    def new(self, name):
        if self.editable:
            return Variable(self, name)
        else:
            return Constant(self, name)

    def validate(self, owner, name, value, required=True):
        chain = []
        if required:
            chain.append(lambda: self._check_required(owner, name,  value))
        chain.append(lambda: self._check_type(owner, name, value))

        return all(f() for f in chain)

    def _check_required(self, owner, name, value):
        required =\
            self.required(owner) if callable(self.required) else self.required
        if value is None and required:
            raise ValidationError('%s is required' % (name, ))

        return True

    def _check_type(self, owner, name, value):
        if self.type is not None\
                and not isinstance(value, (self.type, type(None))):
            raise ValidationError('%s must be an instance of %r' % (
                name, self.type,
            ))

        return True


class Variable:

    def __init__(self, param, name):
        assert isinstance(param, Parameter)

        self.param = param
        self.name = name

    def __get__(self, inst, owner):
        if inst is None:
            return self.param

        assert isinstance(inst, Message)

        if self.name not in inst.__dict__:
            self.__set__(inst, self.param.default)

        return inst.__dict__[self.name]

    def __set__(self, inst, value):
        assert isinstance(inst, Message)

        inst.__dict__[self.name] = value

    def __delete__(self, instance):
        if self.name in instance.__dict__:
            del instance.__dict__[self.name]


class Constant(Variable):

    def __get__(self, inst, owner):
        if inst is None:
            return self.param

        assert isinstance(inst, (Message, RequestError))
        return self.param.default

    def __set__(self, inst, value):
        assert isinstance(inst, Message)

        raise ValidationError('{0!s} is not editable'.format(self.name))

    def __delete__(self, instance):
        raise ValidationError('{0!s} is not editable'.format(self.name))


class MessageMeta(type):

    def __new__(cls, name, bases, namespace):
        params = {}
        for k, v in namespace.items():
            if not isinstance(v, Parameter):
                continue

            params[k] = v
            namespace[k] = v.new(k)
        else:
            namespace['__msg_params__'] = params

        return super(MessageMeta, cls).__new__(cls, name, bases, namespace)


class Message(dict, metaclass=MessageMeta):

    def __str__(self):
        return self._to_dict().__str__()

    def __repr__(self):
        return self.__str__()

    def _to_dict(self):
        dct = self.copy()
        dct.update((
            k, getattr(self, k)
        ) for k in self.__msg_params__.keys())

        return dct

    def to_json(self):
        self.validate()

        dct = {k: v for k, v in self._to_dict().items() if v is not None}
        return json.dumps(dct)

    def to_query_string(self):
        self.validate()

        return urlencode([
            (k, v) for k, v in self._to_dict().items() if v is not None
        ])

    def validate(self):
        for name, param in self.__msg_params__.items():
            param.validate(self, name, getattr(self, name))

        return True

    def _from_dict(self, D):
        for k, v in D.items():
            if k in self.__msg_params__:
                param = self.__msg_params__[k]
                if param.editable:
                    setattr(self, k, v)
                elif param.default == v:
                    continue
                else:
                    raise ValidationError(
                        '{0!s} must be \'{1!s}\''.format(k, param.default))
            else:
                self[k] = v

    @classmethod
    def from_dict(cls, D):
        inst = cls()
        inst._from_dict(D)
        return inst


class Request(Message):
    response = None
    err_response = None

    def answer(self, provider, owner):
        raise NotImplementedError


class Response(Message):

    def __init__(self, request, *args, **kwargs):
        super(Response, self).__init__(self, *args, **kwargs)
        self.request = request
        self.__redirect_uri = None

    def is_redirect(self):
        raise NotImplementedError

    def get_redirect_to(self):
        assert self.is_redirect()
        assert hasattr(self.request, 'response_type')\
            and self.request.response_type
        assert self.redirect_uri

        if hasattr(self.request, 'response_mode')\
                and self.request.response_mode:
            is_fragment = self.request.response_mode == 'fragment'
        else:
            response_types = set(self.request.response_type.split())
            is_fragment = 'token' in response_types

        parsed = urlparse(self.redirect_uri)
        if is_fragment:
            query = parsed.query
            fragment = self.to_query_string()
        else:
            query = parse_qsl(parsed.query)
            query.extend(parse_qsl(self.to_query_string()))
            query = urlencode(query)
            fragment = parsed.fragment

        return urlunparse(parsed[:4] + (query, fragment))

    def get_content_type(self):
        raise NotImplementedError

    def get_response_body(self):
        raise NotImplementedError

    @property
    def redirect_uri(self):
        return self.__redirect_uri

    @redirect_uri.setter
    def redirect_uri(self, redirect_uri):
        self.__redirect_uri = redirect_uri

    @classmethod
    def from_dict(cls, request, D):
        inst = cls(request)
        inst._from_dict(D)
        return inst


class AccessTokenResponse(Response):
    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int, recommended=True)
    refresh_token = Parameter(str)
    scope = Parameter(str)

    def is_redirect(self):
        return False

    def get_content_type(self):
        return 'text/json;charset=utf8'

    def get_response_body(self):
        return self.to_json()


class ErrorResponse(Response):
    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)

    def is_redirect(self):
        return False

    def get_content_type(self):
        return 'text/json;charset=utf8'

    def get_response_body(self):
        return self.to_json()


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


class InvalidRequet(RequestError):
    kind = Parameter(str, default='invalid_request', editable=False)

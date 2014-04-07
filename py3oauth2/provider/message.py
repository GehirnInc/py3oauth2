# -*- coding: utf-8 -*-

import json

from .exceptions import ValidationError


class Value:

    def __init__(self, param, name, value):
        assert isinstance(param, Parameter)

        self.param = param
        self.name = name
        self.__set__(self, value)

    def __get__(self, inst, owner):
        return self._value

    def __set__(self, inst, value):
        if self.param.type is None\
                or isinstance(value, (self.param.type, type(None))):
            self._value = value
            return

        raise ValidationError('%s must be an instance of %r' % (
            self.name, self.param.type,
        ))


class Parameter:

    def __init__(self, type, required=False, recommended=False, default=None):

        self.type = type
        self.required = required
        self.recommended = recommended
        self.default = default

        self._check_type(self, 'value of argument default', self.default)

    def get_default(self):
        return self.default

    def new(self, name, value):
        return Value(self, name, value)

    def validate(self, owner, name, value, required=True):
        return all((
            self._check_required(owner, name,  value),
            self._check_type(owner, name, value)))

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


class MessageMeta(type):

    def __new__(cls, name, bases, namespace):
        namespace['__msg_params__'] = dict(
            (k, v) for k, v in namespace.items() if isinstance(v, Parameter)
        )
        return super(MessageMeta, cls).__new__(cls, name, bases, namespace)


class Message(dict, metaclass=MessageMeta):

    def __new__(cls, *args, **kwargs):
        inst = super(Message, cls).__new__(cls, *args, **kwargs)
        for name, value in cls.__msg_params__.items():
            setattr(inst, name, value.new(name, value.get_default()))

        return inst

    def __getattribute__(self, name):
        value = super(Message, self).__getattribute__(name)
        if hasattr(value, '__get__'):
            return value.__get__(None, self)

        return value

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

        dct = dict((k, v) for k, v in self._to_dict().items() if v is not None)
        return json.dumps(dct)

    def validate(self):
        for name, param in self.__msg_params__.items():
            param.validate(self, name, getattr(self, name))

        return True

    @classmethod
    def from_dict(cls, D):
        inst = cls()
        for k, v in D.items():
            if hasattr(inst, k):
                setattr(inst, k, v)
            else:
                inst[k] = v

        inst.validate()
        return inst


Request = type('Request', (Message, ), {})


class Response(Message):

    def __init__(self, request, *args, **kwargs):
        super(Response, self).__init__(self, *args, **kwargs)
        self.request = request

    @classmethod
    def from_dict(cls, request, D):
        inst = cls(request)
        for k, v in D.items():
            if hasattr(inst, k):
                setattr(inst, k, v)
            else:
                inst[k] = v

        inst.validate()
        return inst


class AccessTokenResponse(Response):
    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int, recommended=True)
    refresh_token = Parameter(str)
    scope = Parameter(str)

    @classmethod
    def from_request(cls, request, token):
        D = {
            'access_token': token.get_token(),
            'token_type': token.get_type(),
            'expires_in': token.get_expires_in(),
            'refresh_token': token.get_refresh_token(),
        }
        if hasattr(request, 'scope') and request.scope != token.get_scope():
            D['scope'] = token.get_scope()

        return cls.from_dict(request, D)


class ErrorResponse(Response):

    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)


class RefreshTokenRequest(Request):
    response = AccessTokenResponse
    err_response = ErrorResponse

    grant_type = Parameter(str, required=True)
    refresh_token = Parameter(str, required=True)
    scope = Parameter(str)

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
        if not (self.param.type is None or isinstance(value, self.param.type)):
            raise ValidationError('%s must be an instance of %r' % (
                self.name, self.param.type,
            ))

        self._value = value


class Parameter:

    def __init__(self, type, required=False, recommended=False):
        self.type = type
        self.required = required
        self.recommended = recommended

    def new(self, name, value):
        return Value(self, name, value)

    def validate(self, owner, name, value):
        if value is not None and not isinstance(value, self.type):
            raise ValidationError('%s must be an instance of %r' % (
                name, self.type,
            ))

        if callable(self.required) and self.required(owner) or self.required:
            if value is None:
                raise ValidationError('%s is required' % (name, ))


class MessageMeta(type):

    def __new__(cls, name, bases, namespace):
        namespace['__msg_params__'] = dict(
            (k, v) for k, v in namespace.items() if isinstance(v, Parameter)
        )
        return super(MessageMeta, cls).__new__(cls, name, bases, namespace)


class Message(dict, metaclass=MessageMeta):

    def __setattr__(self, name, value):
        try:
            current = getattr(self, name)
        except AttributeError:
            super(Message, self).__setattr__(name, value)
        else:
            if name in self.__msg_params__ and current is None:
                super(Message, self).__setattr__(
                    name, self.__msg_params__[name].new(name, value)
                )
                return

            super(Message, self).__setattr__(name, value)

    def __getattribute__(self, name):
        value = super(Message, self).__getattribute__(name)
        if isinstance(value, Parameter):
            return None
        elif hasattr(value, '__get__'):
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


class RefreshTokenRequest(Request):

    grant_type = Parameter(str, required=True)
    refresh_token = Parameter(str, required=True)
    scope = Parameter(str)


class AccessTokenResponse(Response):
    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int, recommended=True)
    refresh_token = Parameter(str)
    scope = Parameter(str)


class ErrorResponse(Response):

    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)

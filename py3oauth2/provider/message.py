# -*- coding: utf-8 -*-

import json


class Value:

    def __init__(self, param, value):
        assert isinstance(param, Parameter)

        self.type = param.type
        self.required = param.required
        self.recommended = param.recommended
        self.__set__(self, value)

    def __get__(self, inst, owner):
        return self._value

    def __set__(self, inst, value):
        if not (self.type is None or isinstance(value, self.type)):
            raise ValueError()

        self._value = value


class Parameter:

    def __init__(self, type, required=False, recommended=False):
        self.type = type
        self.required = required
        self.recommended = recommended

        self._value = None

    def new(self, value):
        return Value(self, value)


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
                    name, self.__msg_params__[name].new(value)
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

    @classmethod
    def from_dict(cls, D):
        inst = cls()
        for k, v in D.items():
            if hasattr(inst, k):
                setattr(inst, k, v)
            else:
                inst[k] = v

        return inst


class RefreshTokenRequest(Message):

    grant_type = Parameter(str, required=True)
    refresh_token = Parameter(str, required=True)
    scope = Parameter(str)


class AccessTokenResponse(Message):
    access_token = Parameter(str, required=True)
    token_type = Parameter(str, required=True)
    expires_in = Parameter(int, recommended=True)
    refresh_token = Parameter(str)
    scope = Parameter(str)


class ErrorResponse(Message):

    error = Parameter(str, required=True)
    error_descritpion = Parameter(str)
    error_uri = Parameter(str)

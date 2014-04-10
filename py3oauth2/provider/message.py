# -*- coding: utf-8 -*-

import json

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

        if self.param.validate(inst, self.name, value, False):
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

        dct = dict((k, v) for k, v in self._to_dict().items() if v is not None)
        return json.dumps(dct)

    def validate(self):
        for name, param in self.__msg_params__.items():
            param.validate(self, name, getattr(self, name))

        return True

    def _from_dict(self, D):
        for k, v in D.items():
            if k in self.__msg_params__:
                setattr(self, k, v)
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

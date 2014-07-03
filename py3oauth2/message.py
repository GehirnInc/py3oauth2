# -*- coding: utf-8 -*-

import json
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    urlunparse,
)

from py3oauth2.exceptions import ValidationError


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

        if not isinstance(value, self.param.type):
            if isinstance(value, str)\
                    and self.param.type is int\
                    and value.isdigit():
                value = int(value, 10)

        inst.__dict__[self.name] = value

    def __delete__(self, instance):
        if self.name in instance.__dict__:
            del instance.__dict__[self.name]


class Constant(Variable):

    def __get__(self, inst, owner):
        if inst is None:
            return self.param

        return self.param.default

    def __set__(self, inst, value):
        assert isinstance(inst, Message)

        raise ValidationError('{0!s} is not editable'.format(self.name))

    def __delete__(self, instance):
        raise ValidationError('{0!s} is not editable'.format(self.name))


class MessageMeta(type):

    def __new__(cls, name, bases, namespace):
        for k, v in namespace.items():
            if not isinstance(v, Parameter):
                continue

            namespace[k] = v.new(k)

        return super(MessageMeta, cls).__new__(cls, name, bases, namespace)


class Message(dict, metaclass=MessageMeta):

    def __str__(self):
        return self._to_dict().__str__()

    def __repr__(self):
        return self.__str__()

    def _to_dict(self):
        dct = self.copy()
        for cls in self.__class__.__mro__:
            if not isinstance(cls, MessageMeta):
                continue

            for key in vars(cls):
                if key in dct:
                    continue

                value = getattr(cls, key)
                if not isinstance(value, Parameter):
                    continue
                dct[key] = getattr(self, key)

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
        for cls in self.__class__.__mro__:
            if not isinstance(cls, MessageMeta):
                continue

            for key in vars(cls):
                value = getattr(cls, key)
                if not isinstance(value, Parameter) or\
                        getattr(self.__class__, key) is not value:
                    continue

                value.validate(self, key, getattr(self, key))

        return True

    def update(self, D):
        for k, v in D.items():
            try:
                value = getattr(self.__class__, k)
                if not isinstance(value, Parameter):
                    self[k] = v
                    continue

                if value.editable:
                    setattr(self, k, v)
                elif value.default == v:
                    continue
                else:
                    raise ValidationError('{0!s} must be \'{1!s}\''.format(
                        k, value.default
                    ))
            except (AttributeError, TypeError):
                self[k] = v


def is_state_required(self):
    return hasattr(self.request, 'state') and self.request.state is not None


class Response(Message):

    def __init__(self, request, redirect_uri=None):
        self.request = request
        self.redirect_uri = redirect_uri

    def is_redirect(self):
        return hasattr(self.request, 'response_type')\
            and isinstance(self.redirect_uri, str)

    def get_redirect_to(self):
        assert self.is_redirect()

        if hasattr(self.request, 'response_mode'):
            response_mode = self.request.response_mode
        else:
            response_mode = self.request.get('response_mode')

        if response_mode:
            is_fragment = response_mode == 'fragment'
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


class Request(Message):
    response = None

    def answer(self, provider, owner):
        raise NotImplementedError

# -*- coding: utf-8 -*-

import json
import unittest

from . import (
    Request,
    Response,
)


class TestParameter(unittest.TestCase):

    @property
    def target_class(self):
        from ..message import Parameter
        return Parameter

    def test_new_atom(self):
        from ..message import Constant
        inst = self.target_class(str, editable=False)
        self.assertIsInstance(inst.new('name'), Constant)

    def test_new_value(self):
        from ..message import Variable
        inst = self.target_class(str)
        self.assertIsInstance(inst.new('name'), Variable)

    def test_validate(self):
        from ..exceptions import ValidationError
        inst = self.target_class(str, required=True)

        self.assertTrue(inst.validate(None, 'value', 'value'))
        with self.assertRaises(ValidationError):
            self.assertTrue(inst.validate(None, 'value', None))
        self.assertTrue(
            inst.validate(None, 'value', 'value', required=False))

        with self.assertRaises(ValidationError):
            inst.validate(None, 'value', 123)

        with self.assertRaises(ValidationError):
            inst.validate(None, 'value', 123, required=False)

    def test_validate_required_func(self):
        from ..exceptions import ValidationError
        inst = self.target_class(
            str, required=lambda owner: hasattr(owner, 'name'))

        self.assertTrue(inst.validate(None, 'value', None))
        with self.assertRaises(ValidationError):
            inst.validate(type('Dummy', (object, ), {'name': 'value'})(),
                          'value', None)
        self.assertTrue(inst.validate(
            type('Dummy', (object, ), {'name': 'value'})(), 'value', 'value'))


class TestVariable(unittest.TestCase):

    def setUp(self):
        from ..message import (
            Message,
            Parameter,
        )
        self.foo = Parameter(str)
        self.bar = Parameter(str, default='hoge')
        self.msg = type('cls', (Message, ), {
            'foo': self.foo,
            'bar': self.bar,
        })

    def test_it(self):
        self.assertEqual(self.msg.foo, self.foo)
        self.assertEqual(self.msg.bar, self.bar)

        inst = self.msg()
        self.assertIsNone(inst.foo)
        self.assertEqual(inst.bar, 'hoge')

        inst.foo = inst.bar = 'value'
        self.assertEqual(inst.foo, 'value')
        self.assertEqual(inst.bar, 'value')

        from ..exceptions import ValidationError
        inst.foo = 123
        with self.assertRaises(ValidationError):
            inst.validate()

        del inst.foo
        self.assertIsNone(inst.foo)

        del inst.bar
        self.assertEqual(inst.bar, 'hoge')


class TestConstant(unittest.TestCase):

    def setUp(self):
        from ..message import (
            Message,
            Parameter,
        )
        self.foo = Parameter(str, default='foo', editable=False)
        self.msg = type('cls', (Message, ), {
            'foo': self.foo,
        })

    def test_it(self):
        self.assertEqual(self.msg.foo, self.foo)

        inst = self.msg()
        self.assertEqual(inst.foo, 'foo')

        from ..exceptions import ValidationError
        with self.assertRaises(ValidationError):
            inst.foo = 'hoge'

        with self.assertRaises(ValidationError):
            del inst.foo


class TestMessageMeta(unittest.TestCase):

    def test_it(self):
        from ..message import (
            Constant,
            Parameter,
            MessageMeta,
            Variable,
        )

        foo = Parameter(str)
        bar = Parameter(str, editable=False)
        cls = MessageMeta('cls', (), {
            'foo': foo,
            'bar': bar,
        })

        self.assertTrue(hasattr(cls, '__msg_params__'))
        self.assertEqual(cls.__msg_params__, {
            'foo': foo,
            'bar': bar,
        })

        self.assertIsInstance(cls.__dict__['foo'], Variable)
        self.assertIsInstance(cls.__dict__['bar'], Constant)


class TestMessage(unittest.TestCase):

    def setUp(self):
        from ..message import (
            Message,
            Parameter,
        )
        self.msg = type('cls', (Message, ), {
            'foo': Parameter(str, editable=False),
        })

    def test_it(self):
        inst = self.msg()
        self.assertEqual(inst._to_dict(), {'foo': None})

        inst['bar'] = 'value'
        self.assertEqual(inst._to_dict(), {'foo': None, 'bar': 'value'})

        self.assertEqual(eval(str(inst)), inst._to_dict())
        self.assertEqual(eval(repr(inst)), inst._to_dict())

        self.assertEqual(json.loads(inst.to_json()), {'bar': 'value'})

        inst = self.msg.from_dict({
            'bar': 'value',
        })
        self.assertIsNone(inst.foo)
        self.assertEqual(inst['bar'], 'value')

        from ..exceptions import ValidationError
        with self.assertRaises(ValidationError):
            inst = self.msg.from_dict({
                'foo': 'value',
            })


class TestRequestErrorMeta(unittest.TestCase):

    @property
    def target_class(self):
        from ..message import RequestErrorMeta
        return RequestErrorMeta

    def test_it(self):
        from ..message import (
            Parameter,
            RequestError,
        )

        self.target_class('cls', object, {})

        with self.assertRaises(AttributeError):
            self.target_class('cls', (RequestError, ), {})

        with self.assertRaises(AttributeError):
            self.target_class('cls', (RequestError, ), {
                'kind': 'value',
            })

        self.target_class('cls', (RequestError, ), {
            'kind': Parameter(str),
        })


class TestResponse(unittest.TestCase):

    def test_is_redirect(self):
        inst = Response(Request())
        with self.assertRaises(NotImplementedError):
            inst.is_redirect()

    def test_get_redirect_to_code(self):
        req = Request.from_dict({
            'grant_type': 'test',
            'response_type': 'code',
        })
        inst = Response.from_dict(req, {
            'param': 'value',
        })
        inst.redirect_uri = 'http://example.com/cb'
        inst.is_redirect = lambda: True

        self.assertEqual(inst.get_redirect_to(),
                         'http://example.com/cb?param=value')

    def test_get_redirect_to_token(self):
        req = Request.from_dict({
            'grant_type': 'test',
            'response_type': 'token',
        })
        inst = Response.from_dict(req, {
            'param': 'value',
        })
        inst.redirect_uri = 'http://example.com/cb'
        inst.is_redirect = lambda: True

        self.assertEqual(inst.get_redirect_to(),
                         'http://example.com/cb#param=value')

    def test_get_redirect_to_response_mode(self):
        req = Request.from_dict({
            'grant_type': 'test',
            'response_type': 'code',
            'response_mode': 'fragment',
        })
        inst = Response.from_dict(req, {
            'param': 'value',
        })
        inst.redirect_uri = 'http://example.com/cb'
        inst.is_redirect = lambda: True

        self.assertEqual(inst.get_redirect_to(),
                         'http://example.com/cb#param=value')

    def test_get_content_type(self):
        inst = Response(Request.from_dict({
            'grant_type': 'test',
        }))
        with self.assertRaises(NotImplementedError):
            inst.get_content_type()

    def test_get_response_body(self):
        inst = Response(Request.from_dict({
            'grant_type': 'test',
        }))
        with self.assertRaises(NotImplementedError):
            inst.get_response_body()


"""The aim of the test is to check binding of hash_algo for classes of kex*
modules.
"""


import hashlib
import inspect
import unittest
from functools import wraps
from types import MethodType


class DummyTransport(object):
    """Dummy transport for the test."""
    def __init__(self):
        self.kexgss_ctxt = None


def _wrap_hashlib_functions():
    """Decorate hashlib.* functions. This will change a type for a particular
    objects."""

    def _wrapper(function):
        @wraps(function)
        def _wrapped(*args, **kwargs):
            return function(*args, **kwargs)
        return _wrapped

    callable_attrs = {
        attr_name: getattr(hashlib, attr_name)
        for attr_name in dir(hashlib)
        if not attr_name.startswith('_')
        and callable(getattr(hashlib, attr_name))
    }

    hashlib_initial_functions = {}
    for attr_name, attr_obj in callable_attrs.items():
        hashlib_initial_functions[attr_name] = attr_obj
        setattr(hashlib, attr_name, _wrapper(attr_obj))

    return hashlib_initial_functions


def _unwrap_hashlib_functions(hashlib_initial_functions):
    """Returns back initial hashlib functions."""

    for attr_name, attr_obj in hashlib_initial_functions.items():
        setattr(hashlib, attr_name, attr_obj)


def _hash_algo_test_call(self):
    """We will bind the function to Kex* classes instances later."""
    return self.hash_algo()


class BindingTest(unittest.TestCase):
    """The test case."""

    def setUp(self):
        self.hashlib_initial_functions = _wrap_hashlib_functions()
        # paramiko import must be done only after a call of
        # _wrap_hashlib_functions because we want to provide paramiko classes
        # with wrapped hashlib functions
        self.paramiko = __import__("paramiko")

    def tearDown(self):
        del self.paramiko
        _unwrap_hashlib_functions(self.hashlib_initial_functions)

    def test_hash_algo_binding(self):
        """Test's payload."""

        modules_to_check = (
            obj for obj in (
                getattr(self.paramiko, attr_name)
                for attr_name in dir(self.paramiko)
                if attr_name.startswith("kex_")
                )
            if inspect.ismodule(obj)
            )

        classes_to_test = (
            obj for obj in (
                getattr(module, attr_name)
                for module in modules_to_check
                for attr_name in dir(module)
                if attr_name.startswith('Kex')
                )
            if inspect.isclass(obj) and hasattr(obj, 'hash_algo')
            )

        instances = [
            klass(transport=DummyTransport()) for klass in classes_to_test]

        for i in instances:
            i.hash_algo_test_call = MethodType(_hash_algo_test_call, i)
            try:
                print(i.hash_algo_test_call())
            except TypeError:
                self.fail(
                    ("Call of hash_algo for an instance of %s raised the "
                     "exception unexpectedly.") % i.__class__)

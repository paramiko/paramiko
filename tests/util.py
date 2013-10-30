import os
import unittest

root_path = os.path.dirname(os.path.realpath(__file__))


class ParamikoTest(unittest.TestCase):
    # for Python 2.3 and below
    if not hasattr(unittest.TestCase, 'assertTrue'):
        assertTrue = unittest.TestCase.failUnless
    if not hasattr(unittest.TestCase, 'assertFalse'):
        assertFalse = unittest.TestCase.failIf


def test_path(filename):
    return os.path.join(root_path, filename)


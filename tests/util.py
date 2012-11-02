import unittest


class ParamikoTest(unittest.TestCase):
    # for Python 2.3 and below
    if not hasattr(unittest.TestCase, 'assertTrue'):
        assertTrue = unittest.TestCase.failUnless
    if not hasattr(unittest.TestCase, 'assertFalse'):
        assertFalse = unittest.TestCase.failIf


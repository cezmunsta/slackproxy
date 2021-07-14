"""
The test suite for all tests
"""

import logging
import unittest

from twisted.python.modules import getModule


class TestSuite(unittest.TestSuite):
    """
    Customised TestSuite
    """
    def __init__(self, tests=()):
        self._tests = []
        self._removed_tests = 0
        for test in tests:
            if test.__module__.startswith('libsrv.test.'):
                logging.warning('Test removed: %r', test)
                self._removed_tests += 1
            else:
                self.addTest(test)


class TestLoader(unittest.TestLoader):
    """
    Customised TestLoader
    """
    suiteClass = TestSuite


def suite():
    """
    Auto-discover test suite

    :return: the TestSuite
    :rtype: unittest.TestSuite
    """
    loader = TestLoader()
    return loader.discover(getModule(__name__).filePath.parent().path, pattern='test_*.py')


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())

"""
Unittests for slackproxy.app

"""
import unittest

from libsrv.test.test_service import ServiceTestCase
from slackproxy import app

SLACKPROXY_SERVER_ARGS = {
    'db_name': 'test.db',
    'debug': True,
}


class AppTestCase(ServiceTestCase):
    """
    Test case for SlackProxy
    """
    def setUp(self) -> None:
        """

        :return:
        """
        super().setUp()
        self._app = app.SlackProxy(**SLACKPROXY_SERVER_ARGS)

    def test_run(self) -> None:
        """

        :return:
        """
        self.srv = self._app
        super().test_run()


if __name__ == '__main__':
    unittest.main()

"""
Unittests for slackproxy.app

"""
import unittest

from libsrv.test.test_service import ServiceTestCase
from slackproxy import app

SERVER_ARGS = ServiceTestCase.DEFAULT_CONFIG.copy()
SERVER_ARGS.update({'db_name': 'test.db', 'debug': True, })


class AppTestCase(ServiceTestCase):
    """
    Test case for SlackProxy
    """
    DEFAULT_CONFIG = SERVER_ARGS.copy()

    _database = SERVER_ARGS['db_name']

    def setUp(self) -> None:
        """
        Shared configuration and preparation tasks

        :return:
        """
        super().setUp()
        self.srv = app.SlackProxy(**SERVER_ARGS)

    def test_run(self) -> None:
        """
        Test the generation of a deferred reactor

        :return:
        """
        super().test_run()

    def test_channel_rules(self) -> None:
        """
        Test handling of rules

        :return:
        """
        self.assertEqual(len(self.srv.channel_rules), 0)
        with self.srv.db as dbc:
            try:
                dbc.execute('REPLACE INTO channel_rules VALUES(?, ?, 1)', ('dummy', 'dummy'))
            except sqlite3.OperationalError:
                pass
        self.assertNotEqual(len(self.srv.channel_rules), 0)


if __name__ == '__main__':
    unittest.main()

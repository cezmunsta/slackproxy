# encoding: utf-8
"""
Description

@author: cezmunsta
@copyright: 2016 cezmunsta
@contact: github@incoming-email.co.uk

Overview
"""
# pylint: disable=pointless-string-statement

from argparse import (
    ArgumentParser,
    ArgumentDefaultsHelpFormatter
)
from http import HTTPStatus
import importlib
import json
import os
import time

import requests
from retrying import retry

from twisted.internet import task

from libsrv import (
    __version__,
    BASE_PATH,
)
from libsrv.handlers import JsonResourceHandler
from libsrv.error import (
    AccessDeniedError,
    AuthRequiredError,
    HookNotImplementedError,
)
from libsrv.service import Service
from libsrv.storage import Storage

AUTH_UPDATE_INTERVAL = 1800

EXTERNAL_DEFAULTS = {
    'host': 'localhost',
    'db': 'slackproxy',
    'read_default_file': os.path.join(BASE_PATH, 'etc', 'my.cnf'),
    'read_default_group': 'slackproxy',
}
EXTERNAL_DEFAULTS_MAPPING = (
    ('db_host', 'host'),
    ('db_name', 'db'),
    ('db_conf', 'read_default_file'),
    ('db_conf_group', 'read_default_group'),
)

SLACK_FIELDS = ['channel', 'icon_url', 'attachments']

SYSTEM_DB = os.path.join(BASE_PATH, 'data', 'slackproxy.db')
SYSTEM_DEFAULTS = {
    'hook': None,
    'port': 12345,
    'channel': '@ceri',
    'ssl': {
        'key': os.path.join(BASE_PATH, 'certs', 'server.pem'),
        'cert': os.path.join(BASE_PATH, 'certs', 'server.pem'),
    },
}

__all__ = ['Storage', 'SlackProxy', 'SlackProxyHandler']


def parse_args():
    """
    Retrive runtime configuration options

    >>> opts = parse_args()
    >>> opts.port
    12345
    """
    parser = ArgumentParser(prog='slackproxy',
                            description='Proxy for Slack, with channel rules and auditing',
                            formatter_class=ArgumentDefaultsHelpFormatter)
    main_group = parser.add_argument_group('main options')
    extras_group = parser.add_argument_group('extra options')
    main_group.add_argument('--config', dest='config_file', help="Path to config file")
    main_group.add_argument('--system-db', dest='db_name', default=SYSTEM_DB, help="Path to SQLite storage")
    extras_group.add_argument('--version', action='store_true', help='Show the current version')
    extras_group.add_argument('--verbose', action='store_true', help='Provide additional output')
    extras_group.add_argument('--debug', action='store_true', help='Provide stderr debug output')
    return vars(parser.parse_args())


def retry_if_required(exception):
    """
    Control request retries
    :param exception:
    :return: bool
    """
    return isinstance(exception, RetryException)


class RetryException(Exception):
    """
    Used to control retry requests
    """


class SlackProxy(Service):
    """
    SlackProxy server

    >>> p = SlackProxy(port=12345, config='config.json')
    >>> p.run()
    """
    isLeaf = True
    use_external_data = False

    def __init__(self, **kwargs):
        """
        Initialise the server

        Configuration of the server behaves as follows;

          1. use SYSTEM_DEFAULTS
          2. override and settings from config
          3. override using any additional kwargs

        :param kwargs: configuration variables
        :return: void
        """
        server_args = kwargs.copy()
        server_args.update({
            'site_handler': SlackProxyHandler(),
        })
        super().__init__(**server_args)
        self._auth = {}
        if self.external_data:
            self.log.default.debug('processing external data')
        if not self.channel_rules:
            self.log.default.warning('channel rules need configuring')

    @property
    def external_data(self):
        """
        Managed external data sources

        :return: external data source configuration
        :rtype: dict
        """
        _external_driver = self.config.get('external_driver', 'libsrv.db.SQLiteAdapter')
        _external_config = self.config.get('external_config')
        _external_queries = self.config.get('external_queries')

        if None in [_external_config, _external_queries]:
            return {}
        try:
            driver = importlib.import_module(_external_driver)
        except ImportError:
            module = importlib.import_module('.'.join(_external_driver.split('.')[:-1]))
            driver = getattr(module, _external_driver.split('.')[-1:][0])
        self.use_external_data = True

        self.config['external_data'] = {}
        if _external_queries:
            with driver(**_external_config) as dbc:
                for _type, _sql in list(_external_queries.items()):
                    self.config['external_data'].setdefault(_type, [])
                    dbc.fetchall(_sql)
                    self.config['external_data'][_type].append(dbc.data.pop())
        return self.config['external_data']

    @property
    def channel_rules(self):
        """
        Channel rules

        :return: all known rules for optimised lookups
        :rtype: dict
        """
        if (not self.metadata['rules_updated'] or not self._auth or
                time.time() > (self.metadata['rules_updated'] + self.config['rule_update_interval'])):
            self.log.default.info('updating channel_rules')
            _auth_list = list(self.config.get('external_data', {}).get('auth', [''])).pop()

            for _auth in _auth_list:
                if not _auth:
                    continue
                _api_user = _auth.get('identifier')
                if _api_user:
                    self._auth[_api_user] = {
                        'auth': _auth.get('api_key'),
                        'channels': [u'#{0}'.format(_api_user), u'#{0}_private'.format(_api_user),
                                     u'#{0}-private'.format(_api_user)]
                    }
                    self.metadata['rules_updated'] = time.time()
                    self.log.default.debug('user %s has access to %r', _api_user, self._auth[_api_user]['channels'])

            # noinspection DuplicatedCode
            with self.db as dbc:
                dbc.fetchall('SELECT api_user, channels FROM channel_rules WHERE enabled')
                for rule in dbc.data.pop():
                    try:
                        self._auth.setdefault(rule['api_user'], {})
                    except IndexError:
                        self.log.default.error('bad rule formattting')
                        break
                    except TypeError:
                        self.log.default.error('bad type for rule: %r', rule)
                        break
                    except ValueError:
                        self.log.default.error('bad value for rule: %r', rule)
                        break
                    try:
                        self._auth[rule['api_user']].setdefault('channels', [])
                        if rule['channels']:
                            self._auth[rule['api_user']]['channels'] += rule['channels'].split(',')
                            self.metadata['rules_updated'] = time.time()
                        self.log.default.debug('user %s has access to %r', rule['api_user'],
                                               self._auth[rule['api_user']]['channels'])
                    except IndexError:
                        pass
        return self._auth

    @property
    def filters(self):
        """
        Provide access to filters

        :return: dict
        """
        return self.DEFAULT_FILTERS

    @staticmethod
    def _db_init_config():
        """
        Intialise the database

        TODO: auto-generate config if missing
        Example config data
        1.0 | port | 12345
        1.0 | channel |@ceri
        1.0 | hook | https://xxx
        1.0 | log_level | WARNING
        1.0 | external_config | {"host": "localhost", "db": "slackproxy", "read_default_file": "etc/my.cnf"}
        1.0 | external_queries | {"auth": "SELECT identifier, api_key FROM clients WHERE active"}
        1.0 | auth_update_interval | 300
        1.0 | auth_config | etc/auth.yaml

        :return: database queries to execute
        :rtype: list of tuples
        """
        return [
            ('CREATE TABLE IF NOT EXISTS config ('
             ' version VARCHAR(50) NOT NULL, '
             ' attr VARCHAR(50) NOT NULL, value TEXT, '
             'PRIMARY KEY(version, attr))', ()),
            ('CREATE TABLE IF NOT EXISTS channel_rules ('
             ' api_user TEXT PRIMARY KEY, '
             ' channels TEXT, '
             ' enabled BOOL DEFAULT 1)', ()),
            ('CREATE TABLE IF NOT EXISTS audit_log ('
             ' ts INTEGER, origin VARCHAR, '
             ' ip_addr VARCHAR, '
             ' channel VARCHAR, '
             ' message TEXT, '
             ' dispatched BOOL DEFAULT 0)', ()),
            ('CREATE INDEX IF NOT EXISTS ix_audit_lookup ON audit_log (ts DESC, origin, ip_addr)', ()),
            ('CREATE TRIGGER IF NOT EXISTS audit_block_deletes BEFORE DELETE ON audit_log '
             'FOR EACH ROW BEGIN '
             'SELECT RAISE(FAIL, "Access denied"); '
             'END;', ()),
            ('CREATE TRIGGER IF NOT EXISTS audit_block_updates BEFORE UPDATE ON audit_log '
             'FOR EACH ROW BEGIN '
             'SELECT RAISE(FAIL, "Access denied"); '
             'END;', ()),
        ]


class SlackProxyHandler(JsonResourceHandler):
    """
    SlackProxyHandler

    >>> from twisted.internet import reactor
    >>> from twisted.web import server
    >>> site = server.Site(SlackProxyHandler())
    >>> reactor.listenTCP(80, site)
    >>> reactor.run()
    """

    def auth_user(self, api_user, api_key, channel):
        """
        Authenticate the user

        :param api_user: str
        :param api_key: str
        :param channel: str
        :return: bool
        """
        _user = self._app.channel_rules.get(api_user, {})
        self.log.default.debug('user: %r', [_user.get('channels'), api_user, channel])

        if self._app.use_external_data and (not _user or api_key != _user.get('auth')):
            self.log.default.warning('user not found %s', api_user)
            return False
        if channel in _user.get('channels', {}):
            self.log.default.debug('channel access granted to %s', api_user)
            return True

        _global_user = self._app.channel_rules.get('all')
        if _global_user and channel in _global_user.get('channels', {}):
            self.log.default.debug('global access granted to %s', api_user)
            return True

        return False

    def filter(self):
        """
        Filter requests

        :return: bool
        """
        lookup = 'text' if self._output.get('text') else 'attachments'

        def _find_ip(text):
            """
            Find IP adddresses in text

            :param text:
            :return: None or object
            """
            # TODO: Handle missing expressions
            # TODO: Handle IPv6
            self.log.default.debug('Find IP: %s', text)
            return self._app.filters['ip'].match(text)

        def _format_ip(ip):  # pylint: disable=invalid-name
            """
            Format an IP for replacement

            :param ip:
            :return: string
            """
            self.log.default.debug('Format IP: %s', ip)
            return '.'.join(['xxx', 'xxx'] + ip.split('.')[2:])

        def _process(words):
            """
            Process a string

            :param words:
            :return:
            """
            self.log.default.debug('Words are: %s', words)
            for word in set(words.split(' ')):
                ip = _find_ip(word)  # pylint: disable=invalid-name
                if ip:
                    words = words.replace(ip.string, _format_ip(ip.string))
                    self.log.default.debug('Obfuscating IP: %s', word)
            self.log.default.debug('Words now: %s', words)
            return words

        if lookup == 'attachments':
            current = 0
            for attachment in self._output['attachments']:
                if 'title' in attachment:
                    self._output['attachments'][current]['title'] = _process(attachment['title'])
                if 'text' in attachment:
                    self._output['attachments'][current]['text'] = _process(attachment['text'])
                current += 1
        else:
            self._output['text'] = _process(self._output['text'])
        return True

    @retry(retry_on_exception=retry_if_required, stop_max_attempt_number=3,
           stop_max_delay=30000, wait_random_min=1000, wait_random_max=2000)
    def relay(self, request):
        """
        Relay the reques on to the hook

        :param request:
        :return: bool
        """
        if not self._app.config.get('hook'):
            raise HookNotImplementedError('destination not configured', request)

        # https://api.slack.com/changelog/2016-05-17-changes-to-errors-for-incoming-webhooks
        data = {}
        for k in SLACK_FIELDS:
            if k in self._output:
                data[k] = self._output[k]

        try:
            if 'text' in self._output:
                data['text'] = self._output['text']
                del data['attachments']
        except KeyError:
            pass

        self._output['slack'] = requests.post(self._app.config.get('hook'), json=data)
        if self._output['slack'].status_code in [429, 500]:
            if self._output['slack'].status_code == 429:
                time.sleep(self._output['slack'].getHeader('Retry-After', 10))
            raise RetryException('failed to send - {0}'.format(self._output['slack'].status_code))
        return self._output['slack'].ok

    def audit(self, tstamp, user, ip_addr, channel, message, dispatched):  # pylint: disable=too-many-arguments
        """
        Log messages passing in to the relay

        :param tstamp:
        :param user:
        :param ip_addr:
        :param channel:
        :param message:
        :param dispatched:
        :return: bool
        """
        with self._app.db as dbc:
            if not dbc.execute('INSERT INTO audit_log (ts, origin, ip_addr, channel, message, dispatched) '
                               'VALUES(?, ?, ?, ?, ?, ?)', (tstamp, user, ip_addr, channel, message, dispatched)):
                self.log.default.warning('audit_log failed: %s', json.dumps({
                    'ts': tstamp,
                    'origin': user,
                    'ip_addr': ip_addr,
                    'channel': channel,
                    'message': message,
                    'dispatched': dispatched
                }))
        return True

    def render_POST(self, request):  # pylint: disable=invalid-name
        """
        Handle POST requests

        :param request:
        :return: JSON
        """
        _data = request.content.read()
        _code = 500
        _dispatched = False

        request.setHeader('Content-Type', 'application/json')
        request.setHeader('Server', 'SlackProxy')

        try:
            self._output = json.loads(_data)
            self._output['user'] = request.getHeader('api-user')
            self._output['key'] = request.getHeader('api-key')
            audit_data = self._output.copy()

            if not self._output.get('user') or not self._output.get('key'):
                raise AuthRequiredError('please provide identification', request)
            if not self.auth_user(self._output['user'], self._output['key'], self._output.get('channel')):
                raise AccessDeniedError('permission denied', request)

            self.filter()
            self.relay(request)

            _dispatched = True
            _code = self._output['slack'].status_code

            self._output = {
                'message': self._output['slack'].text,
                'reason': self._output['slack'].reason,
                'status': _code
            }
        except ValueError:
            self._output = {
                'error': 'JSON data required',
                'status': HTTPStatus.INTERNAL_SERVER_ERROR
            }
        except (AuthRequiredError, AccessDeniedError, HookNotImplementedError) as err:
            self._output = err.message
            _code = int(err.status)
        finally:
            remote_addr = request.getHeader('X-Real-IP')
            if not remote_addr:
                remote_addr = request.getClientAddress()
            self.audit(time.time(), audit_data.get('user'), remote_addr.host, audit_data.get('channel'),
                       _data, int(_dispatched))
            request.setResponseCode(_code)
        return json.dumps(self._output).encode('utf-8')


if __name__ == '__main__':
    task.react(SlackProxy(**parse_args()).run)

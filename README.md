# slackproxy

This is a Twisted-based server that provides proxy service to a remote endpoint,
indended for use with Slack although any JSON-based endpoint should work.

Unlike Slack itself, this provides a means of authenticating access, filtering
and auditing messages that go through it.

## Configuration, access control and logging

An sqlite database is used as the storage layer, although it would be easiy
modified to use something such as RabbitMQ, MySQL, etc by extending the
app.Storage model with a new adapter that inherits from db.DBAdapter. The
app.SlackProxy._setup_db method would then need overriding to suit.

### Installation and configuration

When the app starts it will initialise the schema used for storage.

```sqlite
CREATE TABLE config ( version VARCHAR(50) NOT NULL,  attr VARCHAR(50) NOT NULL, value TEXT, PRIMARY KEY(version, attr));
CREATE TABLE channel_rules ( api_user TEXT PRIMARY KEY,  channels TEXT,  enabled BOOL DEFAULT 1);
CREATE TABLE audit_log ( ts INTEGER, origin VARCHAR,  ip_addr VARCHAR,  channel VARCHAR,  message TEXT,  dispatched BOOL DEFAULT 0);
CREATE INDEX ix_audit_lookup ON audit_log (ts DESC, origin, ip_addr);
CREATE TRIGGER audit_block_deletes BEFORE DELETE ON audit_log FOR EACH ROW BEGIN SELECT RAISE(FAIL, "Access denied"); END;
CREATE TRIGGER audit_block_updates BEFORE UPDATE ON audit_log FOR EACH ROW BEGIN SELECT RAISE(FAIL, "Access denied"); END;
```

### Config data

At the moment, the configuration is loaded once once only so creating and
populating the config table is advisable to save a restart.

Settings are:
```
hook          - full path to the remote webhook
port          - port to listen on
log_level     - DEBUG, INFO, WARN, WARNING, ERROR, CRIT, CRITICAL, FATAL
mysql_config  - JSON-encode connection details
                  e.g. {"host":"localhost","db":"rdba","read_default_file":"/tmp/my.sandbox.cnf"}
mysql_queries - a set of JSON-mapped queries to use to populate SlackProxy._config
                  e.g. {"auth": "select identifier, api_key from clients where active and not backup_only"}
```

Here is an example config:
```sqlite
sqlite> select * from config;
1.0|port|12345
1.0|channel|@ceri
1.0|hook|https://hooks.slack.com/services/xxx
1.0|log_level|DEBUG
1.1|port|12345
1.1|channel|@cezmunsta
1.1|hook|https://hooks.slack.com/services/xxx
1.1|log_level|DEBUG
1.1|mysql_config|{"host":"localhost","db":"rdba","read_default_file":"/tmp/my.sandbox.cnf"}
1.1|mysql_queries|{"auth": "select identifier, api_key from clients where active and not backup_only"}
```

The config is versioned and is read based-upon slackproxy.app.__version__

### Logging

The audit_log table is append-only and has triggers to prevent deletion without
removal of the triggers or dropping the table completely. File-system access
is therefore desirable for extra control and extract the data in realtime to
a remote location (such as pushing through syslog to Logstash).

#### Access control

Currently, a MySQL source will provide valid user credentials; this requires
mysql_config and mysql_queries to be suitably configured. By default any valid
user will be allowed access to a channel matching their username. Rules can be
configured via the channel_rules table in the main system DB (SQLite), with the
special user of "all" granting access to any valid user for the channels that
it provides.

The query that checks the table is:

```sqlite
SELECT api_user, channels
FROM channel_rules
WHERE (api_user = ? OR api_user = "all") AND enabled
```

You can thus allow access to all users for specific channels and then add
additional user-specific access afterwards; the channel field uses comma-
separated values (e.g. @user,private-tests).


## Usage

There is a helper script to start the process:

```shell
#!/bin/bash

export PYTHON_PATH=lib
cd src
python -m slackproxy.app >debug.log 2>&1 &
```

### No auth
```shell
$ curl --header 'Content-Type: application/json' --insecure https://127.0.0.1:12346/ -X POST -d '{"text": "test"}' --dump-header /dev/stdout
HTTP/1.1 401 Unauthorized
Date: Thu, 29 Sep 2016 10:44:52 GMT
Content-Length: 95
Content-Type: application/javascript
Server: SlackProxy

{"status": 401, "message": "Authorisation required", "reason": "please provide identification"}
```

### Invalid credentials or no available rules
```shell
$ curl --header 'Content-Type: application/json' --header "api-user: ceri" --header "api-key: xxxx" --insecure https://127.0.0.1:12346/ -X POST -d '{"text": "test"}' --dump-header /dev/stdout
HTTP/1.1 403 Forbidden
Date: Thu, 29 Sep 2016 10:44:43 GMT
Content-Length: 70
Content-Type: application/javascript
Server: SlackProxy

{"status": 403, "message": "Forbidden", "reason": "permission denied"}
```

### User allowed, no channel in request
```shell
$ curl --header 'Content-Type: application/json' --header "api-user: ceri" --header "api-key: xxxx" --insecure https://127.0.0.1:12346/ -X POST -d '{"text": "test"}' --dump-header /dev/stdout
HTTP/1.1 403 Forbidden
Date: Thu, 29 Sep 2016 10:47:04 GMT
Content-Length: 70
Content-Type: application/javascript
Server: SlackProxy

{"status": 403, "message": "Forbidden", "reason": "permission denied"}
```

### Hook not configured in config
```shell
$ curl --header 'Content-Type: application/json' --header "api-user: ceri" --header "api-key: xxxx" --insecure https://127.0.0.1:12346/ -X POST -d '{"text": "test", "channel": "@ceri"}' --dump-header /dev/stdout
HTTP/1.1 502 Bad Gateway
Date: Thu, 29 Sep 2016 10:48:19 GMT
Content-Length: 86
Content-Type: application/javascript
Server: SlackProxy

{"status": 502, "message": "Hook unavailable", "reason": "destination not configured"}%
```

### Request made
```shell
$ curl --header 'Content-Type: application/json' --header "api-user: ceri" --header "api-key: xxxx" --insecure https://127.0.0.1:12346/ -X POST -d '{"text": "test message", "channel": "private-tests"}' --dump-header /dev/stdout
HTTP/1.1 200 OK
Date: Thu, 29 Sep 2016 12:02:15 GMT
Content-Length: 48
Content-Type: application/javascript
Server: SlackProxy

{"status": 200, "message": "ok", "reason": "OK"}
```

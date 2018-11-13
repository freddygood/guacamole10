# Auth Token application

## Prequisites

### Creating token signature with bash

```
secret='1234567890'
location="/testlocationlive"
path="/testlive.smil/"
nva="1538337566"
dirs="1"
file="playlist.m3u8"
token=$(echo -n ${path}?nva=${nva}&dirs=${dirs} | openssl sha1 -hmac $secret -binary | xxd -p | cut -c1-20)
```
```
secret='1234567890'
location="/testlocationlive"
path="/testlive.smil/"
nva="1538337566"
ip="127.0.0.1"
dirs="1"
file="playlist.m3u8"
token=$(echo -n ${path}?nva=${nva}&ip=${ip}&dirs=${dirs} | openssl sha1 -hmac $secret -binary | xxd -p | cut -c1-20)
```

### Creating URL

```
echo "$location/token=nva=$nva~dirs=$dirs~hash=0$token$path$file"
```
```
echo "$location/token=nva=$nva~ip=$ip~dirs=$dirs~hash=0$token$path$file"
```

### URL example

```
/testlocationlive/token=nva=1538337566~dirs=1~hash=004acb40fa3d37b94fdcd/testlive.smil/playlist.m3u8
```
```
/testlocationlive/token=nva=1538337566~ip=127.0.0.1~dirs=1~hash=004acb40fa3d37b94fdcd/testlive.smil/playlist.m3u8
```

## Application

### Requirements

Python 2.7
pip
virtualenv
git
gcc

#### Ubuntu

```
apt-get update && \
apt-get install -y python-dev python-pip python-virtualenv git
```

#### RHEL7 / CentOS7

```
yum install -y python-devel python2-pip python-virtualenv git gcc
```

### Clone and prepare environment

#### Common part

```
set -e
mkdir -p /var/lib/auth_token
cd /var/lib/auth_token
git clone --depth 1 https://github.com/freddygood/guacamole10.git app
cd app
virtualenv venv
. venv/bin/activate
pip install --upgrade pip
```

#### Ubuntu

```
pip install -r requirements.txt
deactivate
```

#### RHEL7 / CentOS7

```
pip install -r requirements-rhel.txt
deactivate
```

### Start application manually

```
cd /var/lib/auth_token/app
. venv/bin/activate
uwsgi --ini uwsgi.ini
```

### Start application

#### systemd (Ubuntu 16) / RHEL7 / CentOS7

```
cp /var/lib/auth_token/app/auth_token.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable auth_token.service
systemctl start auth_token.service
```

#### upstart (Ubuntu 14)

```
cp /var/lib/auth_token/app/auth_token.conf /etc/init/
start auth_token
```

### Configuration

There is a config file /var/lib/auth_token/app/config.py for configuration standalone application:

```
host = '0.0.0.0'
port = 8080
debug = True
cache_timeout=60

secret_default = 'qwertyuiop'
secret = {
        'testlocationlive': '1234567890',
        'salloum': 'djdheylsksjlak248du'
}

geoip_blacklist_default = []
geoip_blacklist = {
        'lbcgrouplive': [ 'US', 'AU', 'CA' ],
        'salloum': [ 'US', 'RU', 'NL' ]
}
```

- cache_timeout - time to cache validate token function (integer)
- secret_default - default secret (string)
- secret - secret by location (dict). Used during the validation token. The script matches first part of URL (with no leading slash) with keys of the dictionary. If a key not found the default secret will be used. For example:

- /testlocationlive/token.. - secret `1234567890` will be used
- /verynicelocation/token.. - secret `qwertyuiop` will be used

- geoip_blacklist_default - default geoip blacklist, usually []
- geoip_blacklist - geoip blacklist by location (dict of lists)

There is /var/lib/auth_token/app/uwsgi.ini file for configuration uwsgi daemon:

```
[uwsgi]

master = true
module = wsgi
socket = 0.0.0.0:8080
processes = 16
harakiri = 15
```

- socket - ip and port to listen
- processes - number of workers, way to scale
- harakiri - kill and restart worker in case it hangs

The application must be restarted to apply configuration files changes

### Restart the application

#### systemd

```
systemctl restart auth_token.service
```

#### upstart

```
restart auth_token.service
```

### Reload the configuration (graceful restart)

#### systemd

```
systemctl reload auth_token.service
```

#### upstart

```
reload auth_token.service
```

#### upstart alternative

If upstart reload doesn't work as expected, to reload run command:
```
ps auxf | grep uwsgi

root     13351  0.0  0.0  87776 20636 ?        S    23:08   0:00  \_ uwsgi --ini uwsgi.ini         <- root process
root     13354  0.0  0.0  87776 14964 ?        S    23:08   0:00      \_ uwsgi --ini uwsgi.ini
root     13355  0.0  0.0  87776 14968 ?        S    23:08   0:00      \_ uwsgi --ini uwsgi.ini
root     13356  0.0  0.0  87776 14968 ?        S    23:08   0:00      \_ uwsgi --ini uwsgi.ini
...
```
Locate root process then send him HUP signal
```
kill -HUP 13351
```

#### crontab job update GeoIP database

To update db nightly

```
cp crontab /etc/cron.daily/auth_token_geoip_db_update
chmod +x /etc/cron.daily/auth_token_geoip_db_update
```

### Deployment

The application might be deployed on the same servers with nginx and on dedicated servers as well.

#### Easy deployment

Each edge server with nginx has it's own instance of application and sends requests to it 127.0.0.1:8080

#### Advanced deployment

There are dedicated servers with the application working in parallel. Requests must be balanced with upstream module in nginx.

## Nginx configuration

### Upstream definition

Insert the block within http section (before servers definition)

```
upstream auth_token {
        server 127.0.0.1:8080;
}
```

### Auth token secured

#### Auth location

Create one location per server

```
# Auth token common location
location = /auth_token {
        internal;
        include uwsgi_params;
        rewrite / $request_uri break;
        uwsgi_pass auth_token;
        uwsgi_pass_request_body off;
}
```

#### Streaming secured location

Create the block per each secured location

```
# Secured testlocationlive location
location /testlocationlive/token {
        log_not_found off;
        auth_request /auth_token;
        error_page 404 =200 @testlocationlive_auth_passed;
}
location @testlocationlive_auth_passed {
        rewrite ^(/testlocationlive)/token=.*hash=[a-z0-9]+(/.*)$ $1$2 last;
}
```

#### Token checking service

Only for dev and test purpose - ability to check validity of token and secured URL without hitting any files

```
# Checking token service
location /_check_auth_token  {
        auth_request /auth_token;
        error_page 404 =200 @check_auth_passed;
}
location @check_auth_passed {
        return 200;
}
```

#### Using token checking service

Response code 200 or 403

```
curl -sv http://nginx.testcdn.yes/_check_auth_token/token=nva=1537000000~dirs=1~hash=06bffd04a860d31992619/testlive.smil/playlist.m3u8
```

### GeoIP secured

#### GeoIP checking locations setup

Create the block per each secured location

```
# GeoIP checking testlocationlive location
location = /testlocationlive/geoip {
        internal;
        include uwsgi_params;
        uwsgi_pass auth_token;
        uwsgi_pass_request_body off;
}
```

Add line to geoip secured location with playlist

```
auth_request /testlocationlive/geoip;
```

#### Example

```
# GeoIP checking location
location = /testlocationlive/geoip {
        internal;
        include uwsgi_params;
        uwsgi_pass auth_token;
        uwsgi_pass_request_body off;
}

location /testlocationlive  {
        location ~* (\.(m3u8|manifest|Manifest|mpd|dvr|DVR))$ {
                auth_request      /testlocationlive/geoip;
                add_header        Chunk-Cache-Status $upstream_cache_status;
                proxy_cache_valid 200 302  2s;
                rewrite           ^/testlocationlive/(.+\.(m3u8|manifest|Manifest|mpd|dvr|DVR))$ /testpublish/$1 break;
                proxy_pass        http://158.179.158.179:11935;
        }
...
```

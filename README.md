# Auth Token application

## Prequisites

### Creating token signature with bash

```
secret='1234567890'
location="/testlocationlive"
path="/testlive.smil/"
nva_pref="?nva="
nva="1538337566"
dir_pref="&dirs="
dirs="1"
file="playlist.m3u8"
token=$(echo -n ${path}?nva=${nva}&dirs=${dirs} | openssl sha1 -hmac $secret -binary | xxd -p | cut -c1-20)
```

### Creating URL

```
echo "$location/token=nva=$nva~dirs=$dirs~hash=0$token$path$file"
```

### URL example

```
/testlocationlive/token=nva=1538337566~dirs=1~hash=004acb40fa3d37b94fdcd/testlive.smil/playlist.m3u8
```

## Application

### Requirements

Python 2.7
virtualenv

### Clone and prepare environment

```
mkdir -p /var/lib/auth_token
cd /var/lib/auth_token
git clone git@github.com:freddygood/guacamole10.git app
cd app
virtualenv venv
. venv/bin/activate
pip install -r requirements.txt
```

### Start application manually

```
cd /var/lib/auth_token/app
. venv/bin/activate
uwsgi --ini uwsgi.ini
```

### Start application via systemd

```
cp /var/lib/auth_token/app/auth_token.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable auth_token.service
systemctl restart auth_token.service
```

## Nginx configuration

### Auth upstream

```
upstream auth_token {
        server 127.0.0.1:8080;
}
```

### Auth location

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

### Token checking service

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

### Using token checking service

Response code 200 or 403

```
curl -sv http://nginx.testcdn.yes/_check_auth_token/token=nva=1537000000~dirs=1~hash=06bffd04a860d31992619/testlive.smil/playlist.m3u8
```

### Streaming secured location

```
# Secured testlocationlive location
location /testlocationlive/token {
        auth_request /auth_token;
        error_page 404 =200 @testlocationlive_auth_passed;
}
location @testlocationlive _auth_passed {
        rewrite ^(/testlocationlive)/token=.*hash=[a-z0-9]+(/.*)$ $1$2 last;
}
```

from flask import Flask, Response, request
from flask_caching import Cache
from werkzeug.routing import BaseConverter
from time import time
from hashlib import sha1
import hmac

"""
TODO
2. logging to files
"""

application = Flask(__name__)
cache = Cache(application, config={'CACHE_TYPE': 'simple'})

import config

expire = getattr(config, 'expire', 30)
host = getattr(config, 'host', '127.0.0.1')
port = getattr(config, 'port', 8080)
debug = getattr(config, 'debug', True)
cache_timeout = getattr(config, 'cache_timeout', 60)

secret_default = getattr(config, 'secret_default', 'my-secret')
secret = getattr(config, 'secret', {})

def log_param(func, prefix, param):
	application.logger.debug("{}: {} = {}".format(func, prefix, param))

def validate_timestamp(timestamp):
	now = int(time())
	log_param('validate_timestamp', 'now', now)
	log_param('validate_timestamp', 'timestamp', timestamp)
	return now < int(timestamp)

"""
creating token signature - bash implementation
path="/lbclive.smil/"
nva_pref="?nva="
nva="1540000000"
ip_pref="?ip="
ip="127.0.0.1"
dir_pref="&dirs="
dirs="1"
file="playlist.m3u8"
token=$(echo -n $path$nva_pref$nva$dir_pref$dirs | openssl sha1 -hmac 'H3ll0!S3c&8' -binary | xxd -p | cut -c1-20)
echo "/token=nva=$nva~dirs=$dirs~hash=0$token$path$file"
token=$(echo -n $path$nva_pref$nva$ip_pref$ip$dir_pref$dirs | openssl sha1 -hmac 'H3ll0!S3c&8' -binary | xxd -p | cut -c1-20)
echo "/token=nva=$nva~ip=$ip~dirs=$dirs~hash=0$token$path$file"
"""

def validate_token(token, timestamp, dirs, path, location, remote_addr = ''):
	calculated_token = calculate_token(timestamp, dirs, path, location, remote_addr)
	log_param('validate_token', 'token', token)
	log_param('validate_token', 'calculated', calculated_token[0:20])
	log_param('validate_token', 'timestamp', timestamp)
	log_param('validate_token', 'dirs', dirs)
	log_param('validate_token', 'path', path)
	log_param('validate_token', 'remote_addr', remote_addr)

	if (hasattr(hmac, 'compare_digest')):
		return hmac.compare_digest(calculated_token[0:20].encode(), token.encode())
	else:
		return calculated_token[0:20].encode() == token.encode()

def get_secret(location):
	if location in secret.keys():
		application.logger.debug("Found secret for location {}".format(location))
		return secret[location]
	else:
		application.logger.debug("Using default secret")
		return secret_default

@cache.memoize(timeout=cache_timeout)
def calculate_token(timestamp, dirs, path, location, remote_addr):
	if remote_addr:
		signature_line = "/{}/?nva={}&ip={}&dirs={}".format(path, timestamp, remote_addr, dirs)
	else:
		signature_line = "/{}/?nva={}&dirs={}".format(path, timestamp, dirs)

	application.logger.debug("Calculation token of {}".format(signature_line))
	return hmac.new(get_secret(location), signature_line, sha1).hexdigest()

class RegexConverter(BaseConverter):
	def __init__(self, url_map, *items):
		super(RegexConverter, self).__init__(url_map)
		self.regex = items[0]

application.url_map.converters['regex'] = RegexConverter

@application.route("/")
def index():
	response = Response()
	response.headers['X-Auth-Token-Status'] = 'Invalid'
	response.status_code = 403
	return response

# /lbcgrouplive/token=nva=1538337566~dirs=1~hash=004acb40fa3d37b94fdcd/lbclive.smil/playlist.m3u8
@application.route('/<location>/token=nva=<timestamp>~dirs=<int:dirs>~hash=0<token>/<path:path>/<file>', methods=['GET'])
def secure_link(token, timestamp, dirs, path, file, location):
	log_param('secure_link', 'token', token)
	log_param('secure_link', 'timestamp', timestamp)
	log_param('secure_link', 'dirs', dirs)
	log_param('secure_link', 'path', path)
	log_param('secure_link', 'file', file)
	log_param('secure_link', 'location', location)

	response = Response()
	if validate_timestamp(timestamp):
		if validate_token(token, timestamp, dirs, path, location):
			response.headers['X-Auth-Token-Path'] = path + '/' + file
			response.headers['X-Auth-Token-Status'] = 'Valid'
		else:
			application.logger.warning("Token {} is invalid".format(token))
			response.headers['X-Auth-Token-Status'] = 'Invalid'
			response.status_code = 403
	else:
		application.logger.warning("Timestamp {} is invalid".format(timestamp))
		response.headers['X-Auth-Token-Status'] = 'Invalid'
		response.status_code = 403

	return response

# /lbcgrouplive/token=nva=1538337566~ip=127.0.0.1~dirs=1~hash=004acb40fa3d37b94fdcd/lbclive.smil/playlist.m3u8
@application.route('/<location>/token=nva=<timestamp>~ip=<ip>~dirs=<int:dirs>~hash=0<token>/<path:path>/<file>', methods=['GET'])
def secure_link_ip(token, timestamp, ip, dirs, path, file, location):
	log_param('secure_link_ip', 'token', token)
	log_param('secure_link_ip', 'timestamp', timestamp)
	log_param('secure_link_ip', 'ip', ip)
	log_param('secure_link_ip', 'dirs', dirs)
	log_param('secure_link_ip', 'path', path)
	log_param('secure_link_ip', 'file', file)
	log_param('secure_link_ip' ,'location', location)

	if request.headers.getlist("X-Forwarded-For"):
		remote_addr = request.headers.getlist("X-Forwarded-For")[0]
	else:
		remote_addr = request.remote_addr
	log_param('secure_link_ip', 'remote_addr', remote_addr)
	response = Response()
	if validate_timestamp(timestamp):
		if validate_token(token, timestamp, dirs, path, location, remote_addr):
			response.headers['X-Auth-Token-Path'] = path + '/' + file
			response.headers['X-Auth-Token-Status'] = 'Valid'
		else:
			application.logger.warning("Token {} is invalid".format(token))
			response.headers['X-Auth-Token-Status'] = 'Invalid'
			response.status_code = 403
	else:
		application.logger.warning("Timestamp {} is invalid".format(timestamp))
		response.headers['X-Auth-Token-Status'] = 'Invalid'
		response.status_code = 403

	return response

if __name__ == "__main__":
	application.run(debug=debug, host=host, port=port)

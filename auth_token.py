from flask import Flask, Response
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

def log_params(prefix, token, timestamp, dirs, path, file = '', location = ''):
	application.logger.debug("{} - path {}".format(prefix, path))
	application.logger.debug("{} - token {}".format(prefix, token))
	application.logger.debug("{} - timestamp {}".format(prefix, timestamp))
	application.logger.debug("{} - dirs {}".format(prefix, dirs))
	if (file):
		application.logger.debug("{} - file {}".format(prefix, file))
	if (location):
		application.logger.debug("{} - location {}".format(prefix, location))

def validate_timestamp(timestamp):
	now = int(time())
	application.logger.debug("Validating timestamp - now {}".format(now))
	application.logger.debug("Validating timestamp - timestamp {}".format(timestamp))
	return now < int(timestamp)

# creating token signature - bash implementation
# path="/lbclive.smil/"
# nva_pref="?nva="
# nva="1538337566"
# dir_pref="&dirs="
# dirs="1"
# file="playlist.m3u8"
# token=$(echo -n $path$nva_pref$nva$dir_pref$dirs | openssl sha1 -hmac 'H3ll0!S3c&8' -binary | xxd -p | cut -c1-20)
# echo "/token=nva=$nva~dirs=$dirs~hash=0$token$path$file"

def validate_token(token, timestamp, dirs, path, location):
	calculated_token = calculate_token(timestamp, dirs, path, location)
	log_params('Validating token', calculated_token[0:20], timestamp, dirs, path)
	return hmac.compare_digest(calculated_token[0:20].encode(), token.encode())

def get_secret(location):
	if location in secret.keys():
		application.logger.debug("Found secret for location {}".format(location))
		return secret[location]
	else:
		application.logger.debug("Using default secret")
		return secret_default

@cache.memoize(timeout=cache_timeout)
def calculate_token(timestamp, dirs, path, location):
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
@application.route('/<location>/token=nva=<timestamp>~dirs=<int:dirs>~hash=0<token>/<path:path>/<file>')
def secure_link(token, timestamp, dirs, path, file, location):
	log_params('Got request parameters', token, timestamp, dirs, path, file, location)
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

if __name__ == "__main__":
	application.run(debug=debug, host=host, port=port)

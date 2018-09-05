from flask import Flask, Response
from werkzeug.routing import BaseConverter
from time import time
from hashlib import sha1
import hmac

"""
TODO
1. caching based on token
2. logging to files
3. add actual URL into response
"""

application = Flask(__name__)

import config

secret = getattr(config, 'secret', 'my-secret')
expire = getattr(config, 'expire', 30)
host = getattr(config, 'host', '127.0.0.1')
port = getattr(config, 'port', 8080)
debug = getattr(config, 'debug', True)

def log_params(prefix, token, timestamp, dirs, path, file = '', location = ''):
	# application.logger.debug("{} - Got request parameters:".format(prefix))
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
def validate_token(token, timestamp, path):
	dirs = path.count('/') + 1
	signature_line = "/{}/?nva={}&dirs={}".format(path, timestamp, dirs)
	calculated_token = hmac.new(secret, signature_line, sha1).hexdigest()
	log_params('Validating token', calculated_token[0:20], timestamp, dirs, path)
	return hmac.compare_digest(calculated_token[0:20].encode(), token.encode())

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
		if validate_token(token, timestamp, path):
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

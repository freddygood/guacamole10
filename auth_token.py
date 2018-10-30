from flask import Flask, Response, request
from flask_caching import Cache
from werkzeug.routing import BaseConverter
from time import time
from hashlib import sha1
import hmac
import geoip2.database

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

geoip_blacklist_default = getattr(config, 'geoip_blacklist_default', [])
geoip_blacklist = getattr(config, 'geoip_blacklist', {})

def validate_timestamp(timestamp):
	now = int(time())
	application.logger.debug('Comparing timestamp {} with now {}'.format(timestamp, now))
	return now < int(timestamp)

@cache.memoize(timeout=cache_timeout)
def validate_geoip(remote_addr, location):

	def get_geoip_blacklist(location):
		if location in geoip_blacklist.keys():
			application.logger.debug("Found geoip blacklist {} for location {}".format(geoip_blacklist[location], location))
			return geoip_blacklist[location]
		else:
			application.logger.debug("Using default geoip blacklist: {}".format(geoip_blacklist_default))
			return geoip_blacklist_default

	if remote_addr == '127.0.0.1':
		application.logger.debug('Skipping geoip check due localhost {}'.format(remote_addr))
		return True

	blacklist = get_geoip_blacklist(location)
	if len(blacklist) == 0:
		application.logger.debug('Skipped geoip check due blacklist is empty')
		return True

	reader = geoip2.database.Reader('GeoLite2/GeoLite2-Country.mmdb')
	try:
		response = reader.country(remote_addr)
	except Exception as e:
		application.logger.error(e)
		return True

	application.logger.debug('Matched country {} for remote IP {}'.format(response.country.iso_code, remote_addr))

	if response.country.iso_code not in blacklist:
		return True
	else:
		return False

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
	if (hasattr(hmac, 'compare_digest')):
		return hmac.compare_digest(calculated_token[0:20].encode(), token.encode())
	else:
		return calculated_token[0:20].encode() == token.encode()

@cache.memoize(timeout=cache_timeout)
def calculate_token(timestamp, dirs, path, location, remote_addr):

	def get_secret(location):
		if location in secret.keys():
			application.logger.debug("Found secret for location {}".format(location))
			return secret[location]
		else:
			application.logger.debug("Using default secret")
			return secret_default

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
	if request.headers.getlist("X-Forwarded-For"):
		remote_addr = request.headers.getlist("X-Forwarded-For")[0]
	else:
		remote_addr = request.remote_addr

	response = Response()
	if validate_timestamp(timestamp):
		response.headers['X-Auth-Timestamp-Status'] = 'Valid'

		if validate_geoip(remote_addr, location):
			response.headers['X-Auth-GeoIP-Status'] = 'Valid'

			if validate_token(token, timestamp, dirs, path, location):
				response.headers['X-Auth-Original-Path'] = path + '/' + file
				response.headers['X-Auth-Token-Status'] = 'Valid'
			else:
				application.logger.warning("Token {} is invalid".format(token))
				response.headers['X-Auth-Token-Status'] = 'Invalid'
				response.status_code = 403
		else:
			application.logger.warning("IP address {} is blacklisted".format(remote_addr))
			response.headers['X-Auth-GeoIP-Status'] = 'Banned'
			response.status_code = 403
	else:
		application.logger.warning("Timestamp {} is invalid".format(timestamp))
		response.headers['X-Auth-Timestamp-Status'] = 'Invalid'
		response.status_code = 403

	return response

# /lbcgrouplive/token=nva=1538337566~ip=127.0.0.1~dirs=1~hash=004acb40fa3d37b94fdcd/lbclive.smil/playlist.m3u8
@application.route('/<location>/token=nva=<timestamp>~ip=<ip>~dirs=<int:dirs>~hash=0<token>/<path:path>/<file>', methods=['GET'])
def secure_link_ip(token, timestamp, ip, dirs, path, file, location):
	if request.headers.getlist("X-Forwarded-For"):
		remote_addr = request.headers.getlist("X-Forwarded-For")[0]
	else:
		remote_addr = request.remote_addr

	response = Response()
	if validate_timestamp(timestamp):
		response.headers['X-Auth-Timestamp-Status'] = 'Valid'

		if validate_geoip(remote_addr, location):
			response.headers['X-Auth-GeoIP-Status'] = 'Valid'

			if validate_token(token, timestamp, dirs, path, location, remote_addr):
				response.headers['X-Auth-Original-Path'] = path + '/' + file
				response.headers['X-Auth-Token-Status'] = 'Valid'
			else:
				application.logger.warning("Token {} is invalid".format(token))
				response.headers['X-Auth-Token-Status'] = 'Invalid'
				response.status_code = 403
		else:
			application.logger.warning("IP address {} is blacklisted".format(remote_addr))
			response.headers['X-Auth-GeoIP-Status'] = 'Banned'
			response.status_code = 403
	else:
		application.logger.warning("Timestamp {} is invalid".format(timestamp))
		response.headers['X-Auth-Timestamp-Status'] = 'Invalid'
		response.status_code = 403

	return response

@application.route('/<location>/geoip', methods=['GET'])
def geoip(location):
	if request.headers.getlist("X-Forwarded-For"):
		remote_addr = request.headers.getlist("X-Forwarded-For")[0]
	else:
		remote_addr = request.remote_addr

	response = Response()
	if validate_geoip(remote_addr, location):
		response.headers['X-Auth-GeoIP-Status'] = 'Valid'
	else:
		application.logger.warning('Remote IP {} is banned'.format(remote_addr))
		response.headers['X-Auth-GeoIP-Status'] = 'Banned'
		response.status_code = 403

	return response

@application.route('/<location>/geoip/<remote_addr>', methods=['GET'])
def geoip_remote_addr(location, remote_addr):
	response = Response()
	if validate_geoip(remote_addr, location):
		response.headers['X-Auth-GeoIP-Status'] = 'Valid'
	else:
		application.logger.warning('Remote IP {} is banned'.format(remote_addr))
		response.headers['X-Auth-GeoIP-Status'] = 'Banned'
		response.status_code = 403

	return response

if __name__ == "__main__":
	application.run(debug=debug, host=host, port=port)

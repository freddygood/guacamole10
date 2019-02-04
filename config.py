host = '::'
port = 8080
debug = True
cache_timeout=60

secret_default = '1234567890'
secret = {
	'lbcgrouplive': 'H3ll0!S3c&8',
	'salloum': 'djdheylsksjlak248du'
}

geoip_blacklist_default = []
geoip_blacklist = {
	'lbcgrouplive': [ 'US', 'AU', 'CA' ],
	'salloum': [ 'US', 'RU', 'NL' ]
}
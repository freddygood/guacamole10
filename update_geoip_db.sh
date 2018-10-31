#!/usr/bin/env bash

set -e

geoip_dir='GeoLite2'
temp_dir='temp'
geoip_file='GeoLite2-Country.mmdb'
geoip_url='http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz'

reload_systemctl='systemctl reload auth_token.service'
reload_upstart='reload auth_token'

rm -rf $temp_dir

mkdir -p $geoip_dir $temp_dir

geoip_archive=$(basename $geoip_url)

curl -s $geoip_url -o - | tar xzf - -C $temp_dir

find $temp_dir -type f -name $geoip_file | xargs -n1 -I{} cp -f {} $geoip_dir/$geoip_file

which systemctl > /dev/null && $reload_systemctl

which reload > /dev/null && $reload_upstart

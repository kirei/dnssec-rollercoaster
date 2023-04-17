#!/bin/bash

if [ ! -f /config/nsd_control.key ]; then
	nsd-control-setup
fi

echo "Starting NSD..."
nsd $NSD_OPTIONS

echo "Starting webserver..."
sed -i 's/^server\.port.*/server.port=8080/' /etc/lighttpd/lighttpd.conf
lighttpd -f /etc/lighttpd/lighttpd.conf

echo "Running DNSSEC Rollercoaster..."
rollercoaster-signer --config-file=/config/rollercoaster.toml --loop

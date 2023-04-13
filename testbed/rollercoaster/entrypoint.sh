#!/bin/bash

if [ ! -f /config/nsd_control.key ]; then
	nsd-control-setup
fi

echo "Starting NSD..."
nsd $NSD_OPTIONS

echo "Starting webserver..."
lighttpd -f /etc/lighttpd/lighttpd.conf

echo "Running DNSSEC Rollercoaster..."
rollercoaster-signer --config-file=/config/rollercoaster.toml --loop

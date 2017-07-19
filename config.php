<?php

class PreviewConfig {

	# Paranoidly check that we are not browsing localhost
	const PARANOID = False;

	# No debugging, thanks
	const DEBUG = False;

    # Be an open HTTP proxy ... REALLY not a good idea (except for testing), unless you like being a proxy for all of china:
	const PROMISCUOUS = False;

    # Preferred DNS: which DNS do we query to suggest an IP - my own
    # authoritative DNS server
	const PREFERRED_DNS = '8.8.8.8'; # e.g. bob.ns.cloudflare.com's IP address

	# Check wildcard: if the DNS points to the same as the wildcard DNS, then discard it
	const CHECK_WILDCARD = False;

	# Add this suffix if there's no dot in the name
	const DNS_SEARCH = 'myserversallhavethisdomain.com';

	# Always accept a destination site on one of these IP addresses
	public $whitelist = array(
		'/^(169\.254\.227\.)/',
		'/^(169\.254\.40\.)/',
	);

	# Target blacklist: things you cannot connect to
	public $blacklist = array(
		'/^(192\.168\.)/',		# RFC1918 unless we want
		'/^(10\.)/',	        # RFC1918 this service
		'/^(172\.1[6-9])/',	    # RFC1918 to be a preview
		'/^(172\.2[0-9])/',	    # RFC1918 window to our
		'/^(172\.3[01])/',	    # RFC1918 private IP's
		'/^(173\.194\.)/',		# google.com
		'/^(69\.171\.)/',		# facebook.com
		'/^(66\.220\.)/',		# facebook.com
	);
}


PyCurl is not suitable for this and [regview](https://github.com/ricardobranco777/regview) was created.
This project is archived.

# registry_view.py
Script to visualize the contents of a Docker Registry v2 using PyCurl

Additional support for AWS EC2 Container Registry with Boto3 (pip3 install boto3)
See https://github.com/boto/boto3 for configuration details

Usage: registry_view.py [OPTIONS]... REGISTRY[:PORT][/REPOSITORY[:TAG][\*]]

Options:

	-c, --cert CERT		Client certificate file name
	-k, --key  KEY		Client private key file name
	-p, --pass PASS		Pass phrase for the private key
	-u, --user USER[:PASS]	Server user and password (for HTTP Basic authentication)
	--digests               Show digests
	--no-trunc		Don't truncate output
	-r, --reverse		Reverse order with the -s & -t options
	-s, --size		Sort images by size with the largest ones coming first
	-t, --time 		Sort images by time with the newest ones coming first
	-v, --verbose		Be verbose. May be specified multiple times

Note: Default port is 443. You must specify "http://..." if running on plain HTTP.

# Docker image

[ricardobranco/registry_view](https://hub.docker.com/r/ricardobranco/registry_view/)

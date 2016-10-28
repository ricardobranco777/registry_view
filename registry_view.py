#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API via curl
#
# v1.5.1 by Ricardo Branco
#
# MIT License

import argparse, base64, json, os, re, string, sys

import time
from calendar import timegm
from datetime import datetime

from getpass import getpass

try:
	import pycurl
except:
	sys.exit("ERROR: Please install PyCurl")

try:
	from io import BytesIO
except ImportError:
	from StringIO import StringIO as BytesIO

if sys.version_info[0] < 3:
	import subprocess

progname = os.path.basename(sys.argv[0])
usage = progname + """ [OPTIONS]... REGISTRY[:PORT]
Options:
	-c, --cert CERT		Client certificate file name
	-k, --key  KEY		Client private key file name
	-p, --pass PASS		Pass phrase for the private key
	-u, --user USER[:PASS]	Server user and password (for HTTP Basic authentication)
        -v, --verbose		Be verbose. May be specified multiple times
"""

parser = argparse.ArgumentParser(usage=usage, add_help=False)
parser.add_argument('-c', '--cert')
parser.add_argument('-k', '--key')
parser.add_argument('-p', '--pass')
parser.add_argument('-u', '--user')
parser.add_argument('-h', '--help', action='store_true')
parser.add_argument('-v', '--verbose', action='count')
parser.add_argument('registry', nargs='?')
args = parser.parse_args()

if args.help or not args.registry:
	print("usage: "+usage)
	sys.exit(not args.help)

registry = args.registry

# Strip any trailing slashes
registry = args.registry.rstrip("/")

# Add scheme, if absent
if not re.match("https?://", registry):
	if registry[-5:] != ":5000":
		registry = "https://"+registry
	else:
		registry = "http://"+registry

# Get credentials from ~/.docker/config.json
def get_creds():
	try:
		f = open(os.path.expanduser("~/.docker/config.json"), "r")
		hostname = re.sub("https?://", "", registry)
		try:
			auth = json.load(f)['auths'][hostname]['auth']
			if auth:
				return base64.b64decode(auth).decode('iso-8859-1')
		finally:
			f.close()
	except:
		pass
	return ""

c = pycurl.Curl()

if args.cert:
	c.setopt(c.SSLCERT, args.cert)
if args.key:
	c.setopt(c.SSLKEY, args.key)
if getattr(args, 'pass'):
	c.setopt(c.KEYPASSWD, getattr(args, 'pass'))
if args.user:
	if not ':' in args.user:
		args.user += ":" + getpass("Password: ")
else:
	args.user = get_creds()
if args.user:
	c.setopt(c.USERPWD, args.user)
if args.verbose:
	c.setopt(c.VERBOSE, args.verbose)
c.setopt(c.SSL_VERIFYPEER, 0)

def curl(url, headers=[]):
	buffer = BytesIO()
	c.setopt(c.URL, registry + url)
	c.setopt(c.WRITEDATA, buffer)
	c.setopt(c.HTTPHEADER, headers)
	try:
		c.perform()
	except	pycurl.error as err:
		print(c.errstr())
		sys.exit(err[0])
	body = buffer.getvalue()
	buffer.close()
	return body.decode('iso-8859-1')

def check_registry():
	if curl("/v2/") != "{}":
		http_code = c.getinfo(pycurl.HTTP_CODE)
		if http_code == 401:
			sys.exit("ERROR: HTTP/1.1 401 Unauthorized. Try docker-login(1) first or specify the -u option")
		elif http_code == 404:
			sys.exit("ERROR: Invalid v2 Docker Registry: " + args[0])
		else:
			sys.exit("ERROR: HTTP " + str(http_code))

def get_repos():
	data = json.loads(curl("/v2/_catalog"))
	data['repositories'].sort()
	return data['repositories']

def get_tags(repo):
	info = curl("/v2/"+repo+"/tags/list")
	data = json.loads(info)
	if info[0:10] == '{"errors":':
		return '', data['errors'][0]['message']
	data['tags'].sort()
	return data['tags'], ''

def get_info(repo, tag):
	data = json.loads(curl("/v2/"+repo+"/manifests/"+tag, ["Accept: application/vnd.docker.distribution.manifest.v1+json"]))
	try:
		data = json.loads(data['history'][0]['v1Compatibility'])
		return [data['created'], data['docker_version']]
	except:
		return '', ''

# Returns truncated image ID (as done by docker-images command)
def get_id(repo, tag):
	data = json.loads(curl("/v2/"+repo+"/manifests/"+tag, ["Accept: application/vnd.docker.distribution.manifest.v2+json"]))
	return data['config']['digest'].replace('sha256:', '')

# Convert date/time string in ISO-6801 format to date(1)

tz = time.strftime('%Z')

def parse_date(ts):
	s = datetime.fromtimestamp(timegm(time.strptime(re.sub("\.\d+Z$", "GMT", ts), '%Y-%m-%dT%H:%M:%S%Z'))).ctime()
	return s[:-4] + tz + s[-5:]

check_registry()

try:	# Python 3
	columns = os.get_terminal_size().columns
except:	# Unix only
	columns = int(subprocess.check_output(['stty', 'size']).split()[1])
cols = int(columns/3)

print("%-*s\t%-12s\t%-30s\t\t%s" % (cols, "Image", "Id", "Created on", "Docker version"))

for repo in get_repos():
	tags, error = get_tags(repo)
	if error:
		print("%-*s\t%-12s\terror: %s" % (cols, repo, "-", error))
		continue
	for tag in tags:
		date, version = get_info(repo, tag)
		if date:
			date = parse_date(date)
		digest = "-"
		if version and int(version.replace('.', '')) > 190:
			digest = get_id(repo, tag)[0:12]
		print("%-*s\t%-12s\t%s\t\t%s" % (cols, repo+":"+tag, digest, date, version))

c.close()


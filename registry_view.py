#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API via curl
#
# v1.3.3 by Ricardo Branco
#
# MIT License

import base64, getopt, json, os, re, string, sys

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
options = """
Options:
	-c, --cert CERT		Client certificate file name
	-k, --key  KEY		Client private key file name
	-p, --pass PASS		Pass phrase for the private key
	-u, --user USER[:PASS]	Server user and password (for HTTP Basic authentication)
"""
usage = "Usage: " + progname + "[OPTIONS]... REGISTRY[:PORT]" + options

c = pycurl.Curl()

userpwd = ""

try:
	opts, args = getopt.getopt(sys.argv[1:], "hc:k:p:u:", ["help", "cert=", "key=", "pass=", "user="])
except	getopt.GetoptError as err:
	sys.exit(usage)
for opt, arg in opts:
	if opt in ("-c", "--cert"):
		c.setopt(c.SSLCERT, arg)
	elif opt in ("-k", "--key"):
		c.setopt(c.SSLKEY, arg)
	elif opt in ("-p", "--pass"):
		if not arg:
			arg = getpass("Client key password: ")
		c.setopt(c.KEYPASSWD, arg)
	elif opt in ("-u", "--user"):
		userpwd = arg
		if not ":" in userpwd:
			userpwd += ":" + getpass("Password: ")
	elif opt in ("-h", "--help"):
		print(usage)
		sys.exit(0)

if len(args) < 1:
	sys.exit(usage)

# Strip any trailing slashes
registry = args[0].rstrip("/")

# Add scheme, if absent
if not re.match("https?://", registry):
	if cert or key or registry[-5:] != ":5000":
		registry = "https://"+registry
	else
		registry = "http://"+registry

# Get credentials from ~/.docker/config.json
def get_creds():
	try:
		f = open(os.path.expanduser("~/.docker/config.json"), "r")
		hostname = re.sub("https?://", "", registry)
		try:
			data = json.load(f)
			auth = data['auths'][hostname]['auth']
			if auth:
				return base64.b64decode(auth).decode('iso-8859-1')
		finally:
			f.close()
	except:
		pass
	return ""

if os.environ.get('DEBUG') is not None:
	c.setopt(c.VERBOSE, 1)
c.setopt(c.SSL_VERIFYPEER, 0)
if not userpwd:
	userpwd = get_creds()
if userpwd:
	c.setopt(c.USERPWD, userpwd)

def curl(url, headers=[]):
	buffer = BytesIO()
	c.setopt(c.URL, registry + url)
	c.setopt(c.WRITEDATA, buffer)
	c.setopt(c.HTTPHEADER, headers)
	try:
		c.perform()
	except	pycurl.error, err:
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
	return data['repositories']

def get_tags(repo):
	info = curl("/v2/"+repo+"/tags/list")

	if info[0:10] != '{"errors":':
		data = json.loads(info)
		return data['tags']
	else:
		return ()

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
	digest = data['config']['digest'].replace('sha256:', '')
	return digest[0:12]

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
	for tag in get_tags(repo):
		date, version = get_info(repo, tag)
		if date:
			date = parse_date(date)
		digest = "-"
		if version and int(version.replace('.', '')) > 190:
			digest = get_id(repo, tag)
		image = repo + ":" + tag
		print("%-*s\t%-12s\t%s\t\t%s" % (cols, image, digest, date, version))

c.close()


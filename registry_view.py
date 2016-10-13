#!/usr/bin/python
#
# Script to visualize the contents of a Docker Registry v2 using the API via curl
#
# v1.0 by Ricardo Branco
#
# MIT License

import json, os, re, string, subprocess, sys

import pycurl

import time
from calendar import timegm
from datetime import datetime

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

progname = os.path.basename(sys.argv[0])
usage = "Usage: " + progname + " REGISTRY[:PORT]"

if len(sys.argv) < 2:
	sys.exit(usage)

# Strip any trailing slashes
registry = sys.argv[1].rstrip("/")

# Add scheme, if absent
if not re.match("https?://", registry):
	if re.search("5000$", registry):
		registry = "http://"+registry
	else:
		registry = "https://"+registry

# Support HTTP Basic Authentication
auth=""
try:
	f = open(os.path.expanduser("~/.docker/config.json"), "r")
	hostname = re.sub("https?://", "", registry)
	try:
		data = json.load(f)
		auth = data['auths'][hostname]['auth']
		if auth != "":
			auth = "Authorization: Basic " + auth
	except:
		pass
	f.close()
except:
	pass

c = pycurl.Curl()

debug = os.environ.get('DEBUG')
if debug != None:
	c.setopt(c.VERBOSE, 1)

def curl(url, headers=[]):
	buffer = BytesIO()
	c.setopt(c.URL, registry + url)
	c.setopt(c.WRITEDATA, buffer)
	c.setopt(c.HTTPHEADER, [auth] + headers)
	c.perform()
	body = buffer.getvalue()
	buffer.close()
	return body.decode('iso-8859-1')

def get_repos():
	data = json.loads(curl("/v2/_catalog"))
	return data['repositories']

def get_tags(repo):
	info = curl("/v2/"+repo+"/tags/list")

	if info[0:10] != '{"errors":':
		data = json.loads(info)
		return data['tags']
	else:
		return []

def get_info(repo, tag):
	data = json.loads(curl("/v2/"+repo+"/manifests/"+tag, ["Accept: application/vnd.docker.distribution.manifest.v1+json"]))
	try:
		data = json.loads(data['history'][0]['v1Compatibility'])
		return [data['created'], data['docker_version']]
	except:
		return ['', '']

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

if curl("/v2/") != "{}":
	sys.exit("ERROR: Invalid v2 registry: " + registry)

# XXX: Unix only
columns = int(subprocess.check_output(['stty', 'size']).split()[1])
cols = int(columns/3)

print("Image".ljust(cols)+'\t'+"Id".ljust(12)+'\t'+'Created on'.ljust(30)+"\t\tDocker version")

for repo in get_repos():
	for tag in get_tags(repo):
		date, version = get_info(repo, tag)
		if date != "":
			date = parse_date(date)
		digest = "-"
		if version and int(version.replace('.', '')) > 190:
			digest = get_id(repo, tag)
		image = repo + ":" + tag
		print(image.ljust(cols) + '\t' + digest.ljust(12) + '\t' + date + "\t\t" + version)

c.close()


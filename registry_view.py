#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API via curl
#
# v1.6.8 by Ricardo Branco
#
# MIT License

from __future__ import print_function

import argparse, base64, json, os, re, string, sys

import time
from calendar import timegm
from datetime import datetime

from getpass import getpass

try:
	import pycurl
except:
	print('ERROR: Please install PyCurl', file=sys.stderr)
	sys.exit(1)

try:
	from io import BytesIO
except ImportError:
	from StringIO import StringIO as BytesIO

if sys.version_info[0] < 3:
	import subprocess

class Curl:
	__headers = {}
	__save_headers = False
	__debug_str = { pycurl.INFOTYPE_TEXT: '* ', pycurl.INFOTYPE_HEADER_IN: '< ', pycurl.INFOTYPE_HEADER_OUT: '> ',
			pycurl.INFOTYPE_DATA_IN: '', pycurl.INFOTYPE_DATA_OUT: '' }

	def __init__(self, **opts):
		self.c = pycurl.Curl()
		for opt, curlopt in (('cert', pycurl.SSLCERT), ('key', pycurl.SSLKEY), ('pass', pycurl.KEYPASSWD),
				('verbose', pycurl.VERBOSE)):
			if opts[opt]: self.c.setopt(curlopt, opts[opt])
		self.c.setopt(pycurl.SSL_VERIFYPEER, 0)
		if opts['verbose'] and opts['verbose'] > 1:
			self.c.setopt(pycurl.DEBUGFUNCTION, self.__debug_function)

	def __del__(self):
		if self.c: self.c.close()

	def __debug_function(self, t, m):
		m = m.decode('iso-8859-1').rstrip()
		if t == pycurl.INFOTYPE_HEADER_OUT:
			m = m.replace('\n', '\n' + self.__debug_str.get(t))
		print(self.__debug_str.get(t) + m)

	# Adapted from https://github.com/pycurl/pycurl/blob/master/examples/quickstart/response_headers.py
	def __header_function(self, header_line):
		if not self.__save_headers:
			return
		# HTTP standard specifies that headers are encoded in iso-8859-1
		header_line = header_line.decode('iso-8859-1')
		# Header lines include the first status line (HTTP/1.x ...)
		if ':' not in header_line:
			if not self.__headers.get('HTTP_STATUS'):
				self.__headers['HTTP_STATUS'] = header_line.strip()
			return
		# Break the header line into header name and value.
		name, value = header_line.split(':', 1)
		# Remove whitespace that may be present.
		name = name.strip()
		value = value.strip()
		# Header names are case insensitive.
		name = name.lower()
		self.__headers[name] = value

	def get(self, url, headers=[], save_headers=False):
		buf = BytesIO()
		__headers = {}
		self.c.setopt(pycurl.URL, url)
		self.c.setopt(pycurl.WRITEDATA, buf)
		self.c.setopt(pycurl.HTTPHEADER, headers)
		self.c.setopt(pycurl.HEADERFUNCTION, self.__header_function)
		self.__save_headers = save_headers
		try:
			self.c.perform()
		except	pycurl.error as err:
			print(self.c.errstr(), file=sys.stderr)
			sys.exit(err.args[0])
		body = buf.getvalue()
		buf.close()
		return body.decode('iso-8859-1')

	def get_headers(self):
		return self.__headers

	def get_http_code(self):
		return self.c.getinfo(pycurl.HTTP_CODE)

class DockerRegistryV2:
	def __init__(self, **args):
		self.__c = Curl(**args)
		self.__registry = args['registry'].rstrip("/")
		# Assume HTTPS by default
		if not re.match("https?://", self.__registry):
			self.__registry = "https://" + self.__registry
		if args['user']:
			if not ':' in args['user']:
				args['user'] += ":" + getpass("Password: ")
		else:
			args['user'] = self.__get_creds()
		self.__c.c.setopt(pycurl.USERPWD, args['user'])
		self.__check_registry()

	def __get(self, url, headers=[], save_headers=False):
		return self.__c.get(self.__registry + "/v2/" + url, headers, save_headers)

	def __check_registry(self):
		if self.__get("", save_headers=True) == "{}":
			return
		http_code = self.__c.get_http_code()
		if http_code == 404:
			error = 'Invalid v2 Docker Registry: ' + self.__registry
		else:
			error = self.__c.get_headers().get('HTTP_STATUS')
			if not error:
				error = "Invalid HTTP server"
		print('ERROR: ' + error, file=sys.stderr)
		sys.exit(1)

	def __get_creds(self):
		try:
			f = open(os.path.expanduser("~/.docker/config.json"), "r")
			hostname = re.sub("^https?://", "", self.__registry)
			try:
				auth = json.load(f)['auths'][hostname]['auth']
				if auth:
					return base64.b64decode(auth).decode('iso-8859-1')
			finally:
				f.close()
		except:	pass

	def get_repositories(self):
		data = json.loads(self.__get("_catalog"))
		data['repositories'].sort()
		return data['repositories']

	def get_tags(self, repo):
		info = self.__get(repo + "/tags/list")
		data = json.loads(info)
		if info.startswith('{"errors":'):
			return '', data['errors'][0]['message']
		data['tags'].sort()
		return data['tags'], ''

	def get_manifest(self, repo, tag, version):
		assert version in (1, 2)
		info = self.__get(repo + "/manifests/" + tag,
			["Accept: application/vnd.docker.distribution.manifest.v" + str(version) + "+json"])
		data = json.loads(info)
		if info.startswith('{"errors":'):
			return '', data['errors'][0]['message']
		return data, ''

	def get_history_items(self, manifest, layer, *items):
		data = json.loads(manifest['history'][layer]['v1Compatibility'])
		if len(items):
			return { key: data[key] for key in items }
		else:
			return dict(data)

if __name__ == "__main__":
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

	if args.help:
		sys.exit('usage: ' + usage)
	elif not args.registry:
		print('usage: ' + usage, file=sys.stderr)
		sys.exit(1)

	# Convert date/time string in ISO-6801 format to date(1)
	tz = time.strftime('%Z')
	def parse_date(ts):
		s = datetime.fromtimestamp(timegm(time.strptime(re.sub("\.\d+Z$", "GMT", ts), '%Y-%m-%dT%H:%M:%S%Z'))).ctime()
		return s[:-4] + tz + s[-5:]

	reg = DockerRegistryV2(**vars(args))

	try:	# Python 3
		columns = os.get_terminal_size().columns
	except:	# Unix only
		columns = int(subprocess.check_output(['stty', 'size']).split()[1])
	cols = int(columns/3)

	print("%-*s\t%-12s\t%-30s\t\t%s" % (cols, "Image", "Id", "Created on", "Docker version"))

	for repo in reg.get_repositories():
		tags, error = reg.get_tags(repo)
		if error:
			print("%-*s\t%-12s\terror: %s" % (cols, repo, "-", error))
			continue
		for tag in tags:
			try:
				manifest, _ = reg.get_manifest(repo, tag, 1)
				items = reg.get_history_items(manifest, 0, 'created', 'docker_version')
				date, version = [parse_date(items['created']), items['docker_version']]
			except:
				date, version = '', ''
			digest = "-"
			if version and int(version.replace('.', '')) > 190:
				manifest, _ = reg.get_manifest(repo, tag, 2)
				digest = manifest['config']['digest'].replace('sha256:', '')
			print("%-*s\t%-12s\t%s\t\t%s" % (cols, repo + ":" + tag, digest[0:12], date, version))


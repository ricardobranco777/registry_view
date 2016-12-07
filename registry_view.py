#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API via curl
#
# Reference: https://github.com/docker/distribution/blob/master/docs/spec/api.md
#
# v1.12.2 by Ricardo Branco
#
# MIT License

from __future__ import print_function

import argparse, base64, json, os, re, string, sys, time

from calendar import timegm
from datetime import datetime
from getpass import getpass

try:
	import pycurl
except	ImportError:
	print('ERROR: Please install PyCurl', file=sys.stderr)
	sys.exit(1)

try:
	from urllib.parse import urlencode
except ImportError:
	from urllib import urlencode

try:
	from io import BytesIO
except	ImportError:
	from StringIO import StringIO as BytesIO

if sys.version_info[0] < 3:
	import subprocess
	input = raw_input

progname = os.path.basename(sys.argv[0])
version = "1.12.2"

usage = "\rUsage: " + progname + """ [OPTIONS]... REGISTRY[:PORT][/REPOSITORY[:TAG]]
Options:
	-c, --cert CERT		Client certificate file name
	-k, --key  KEY		Client private key file name
	-p, --pass PASS		Pass phrase for the private key
	-u, --user USER[:PASS]	Server user and password (for HTTP Basic authentication)
	-v, --verbose		Be verbose. May be specified multiple times
	-V, --version		Show version string and quit

Note: Default PORT is 443. You must prepend "http://" to REGISTRY if running on plain HTTP.
"""

class Curl:
	def __init__(self, **opts):
		self.c = pycurl.Curl()
		curlopts = [('cert', pycurl.SSLCERT), ('key', pycurl.SSLKEY), ('verbose', pycurl.VERBOSE)]
		if hasattr(pycurl, 'KEYPASSWD'):
			curlopts += [('pass', pycurl.KEYPASSWD)]	# Option added to PyCurl 7.21.5
		else:
			curlopts += [('pass', pycurl.SSLCERTPASSWD)]
		for opt, curlopt in curlopts:
			if opts[opt]:
				self.c.setopt(curlopt, opts[opt])
		self.c.setopt(pycurl.SSL_VERIFYPEER, 0)
		if opts['verbose']:
			if opts['verbose'] > 1:
				self.c.setopt(pycurl.DEBUGFUNCTION, self.__debug_function)
		self.c.setopt(pycurl.HEADERFUNCTION, self.__header_function)
		self.c.setopt(pycurl.USERAGENT, '%s/%s %s' % (progname, version, pycurl.version))
		self.buf = BytesIO()
		self.c.setopt(pycurl.WRITEDATA, self.buf)

	def __del__(self):
		self.buf.close()
		self.c.close()

	def __debug_function(self, t, m):
		# Mimic Curl debug output
		curl_prefix = { pycurl.INFOTYPE_TEXT: '* ', pycurl.INFOTYPE_HEADER_IN: '< ', pycurl.INFOTYPE_HEADER_OUT: '> ',
				pycurl.INFOTYPE_DATA_IN: '', pycurl.INFOTYPE_DATA_OUT: '' }

		m = m.decode('iso-8859-1').rstrip()
		if t == pycurl.INFOTYPE_HEADER_OUT:
			m = m.replace(r'\n', r'\n' + curl_prefix[t])
		print(curl_prefix[t] + m)

	# Adapted from https://github.com/pycurl/pycurl/blob/master/examples/quickstart/response_headers.py
	def __header_function(self, header_line):
		# HTTP standard specifies that headers are encoded in iso-8859-1
		header_line = header_line.decode('iso-8859-1')
		# Header lines include the first status line (HTTP/1.x ...)
		if ':' not in header_line:
			if not self.headers.get('HTTP_STATUS'):
				self.headers['HTTP_STATUS'] = header_line.strip()
			return
		# Break the header line into header name and value.
		name, value = header_line.split(':', 1)
		# Remove whitespace that may be present.
		name = name.strip().lower()
		value = value.strip()
		self.headers[name] = value

	def get(self, url, headers=[], auth=None):
		self.headers = {}
		self.buf.seek(0)
		self.buf.truncate()
		self.c.setopt(pycurl.URL, url)
		self.c.setopt(pycurl.HTTPGET, 1)
		self.c.setopt(pycurl.HTTPHEADER, headers)
		if auth:
			self.c.setopt(pycurl.HTTPHEADER, auth)
		try:
			self.c.perform()
		except	pycurl.error as err:
			print(self.c.errstr(), file=sys.stderr)
			sys.exit(err.args[0])
		body = self.buf.getvalue()
		return body.decode(self.get_charset())

	def post(self, url, post_data, auth=None):
		self.buf.seek(0)
		self.buf.truncate()
		self.c.setopt(pycurl.URL, url)
		self.c.setopt(pycurl.POST, 1)
		post_data = urlencode(post_data)
		self.c.setopt(pycurl.POSTFIELDS, post_data)
		if auth:
			self.c.setopt(pycurl.HTTPHEADER, auth)
		try:
			self.c.perform()
		except	pycurl.error as err:
			print(self.c.errstr(), file=sys.stderr)
			sys.exit(err.args[0])
		body = self.buf.getvalue()
		return body.decode(self.get_charset())

	def get_headers(self, key=None):
		if key:
			return self.headers.get(key)
		else:
			return self.headers

	def get_charset(self):
		try:
			match = re.search('charset=(\S+)', self.headers['content-type'])
			if match:
				return match.group(1)
		except	KeyError:
			pass
		return 'iso-8859-1'

	def get_http_code(self):
		return self.c.getinfo(pycurl.HTTP_CODE)

class DockerRegistryError(Exception): pass

class DockerRegistryV2:
	__tz = time.strftime('%Z')
	__cached_manifest = {}
	__basic_auth = ""

	def __init__(self, registry, **args):
		self.__c = Curl(**args)
		self.__registry = registry
		# Assume https:// by default
		if not re.match("https?://", self.__registry):
			self.__registry = "https://" + self.__registry
		if args['user']:
			if not ':' in args['user']:
				args['user'] += ":" + getpass("Password: ")
		else:
			args['user'] = self.__get_creds()
		self.__basic_auth = str(base64.b64encode(args['user'].encode()).decode('ascii'))
		self.__check_registry()

	def __auth_basic(self):
		if not self.__basic_auth:
			userpass = input('Username: ') + ":" + getpass('Password: ')
			self.__basic_auth = str(base64.b64encode(userpass.encode()).decode('ascii'))
		return ['Authorization: Basic ' + self.__basic_auth]

	def __auth_token(self, response_header, use_post=True):
		m = re.match('Bearer realm="([^"]+)",service="([^"]+)"(?:,scope="([^"]+)")?.*', response_header)
		url = m.group(1)
		fields = {}
		for field in ("service", "scope", "account"):
			m = re.match('Bearer realm="(?:[^"]+)".*,' + field + '="([^"]+)"', response_header)
			if m:
				fields[field] = m.group(1)
		if use_post:
			token = json.loads(self.__c.post(url, fields, auth=self.__auth_basic()))['token']
		else:
			url += '?' + urlencode(fields)
			token = json.loads(self.__c.get(url, auth=self.__auth_basic()))['token']
		return ['Authorization: Bearer ' + token]

	def __get(self, url, headers=[]):
		tries = 1
		while True:
			body = self.__c.get(self.__registry + "/v2/" + url, headers)
			http_code = self.__c.get_http_code()
			if http_code == 429:	# Too many requests
				time.sleep(0.1)
				continue
			elif http_code == 401 and tries > 0:
				headers = headers[:]
				auth_method = self.__c.get_headers('www-authenticate')
				if not auth_method or auth_method.startswith('Basic '):
					headers += self.__auth_basic()
				elif auth_method.startswith('Bearer '):
					headers += self.__auth_token(auth_method)
				else:
					print('ERROR: Unsupported authentication method: ' + auth_method, file=sys.stderr)
					sys.exit(1)
			else:
				try:
					data = json.loads(body)
				except	ValueError:
					return body
				if data.get('errors'):
					raise DockerRegistryError(data['errors'][0]['message'])
				else:
					return data
			tries -= 1

	def __check_registry(self):
		if self.__get("") == {}:
			return
		http_code = self.__c.get_http_code()
		if http_code == 404:
			error = 'Invalid v2 Docker Registry: ' + self.__registry
		else:
			error = self.__c.get_headers('HTTP_STATUS')
			if not error:
				error = "Invalid HTTP server"
		print('ERROR: ' + error, file=sys.stderr)
		sys.exit(1)

	def __get_creds(self):
		if not os.path.exists(os.path.expanduser("~/.docker/config.json")):
			return
		auth = ""
		f = open(os.path.expanduser("~/.docker/config.json"), "r")
		config = json.load(f)
		try_registry = [re.sub("^https?://", "", self.__registry)]
		if not re.search(':\d+$', try_registry[0]):
			if self.__registry.startswith('https://'):
				try_registry += [try_registry[0] + ':443']
			elif self.__registry.startswith('http://'):
				try_registry += [try_registry[0] + ':80']
		else:
			if self.__registry.startswith('https://'):
				try_registry += [try_registry[0][:-len(':443')]]
			elif self.__registry.startswith('http://'):
				try_registry += [try_registry[0][:-len(':80')]]
		for registry in try_registry:
			try:
				auth = config['auths'][registry]['auth']
				if auth:
					auth = base64.b64decode(auth).decode('iso-8859-1')
					break
			except	KeyError:
				pass
		f.close()
		return auth

	# Convert date/time string in ISO-6801 format to date(1)
	def __parse_date(self, ts):
		s = datetime.fromtimestamp(timegm(time.strptime(re.sub("\.\d+Z$", "GMT", ts), '%Y-%m-%dT%H:%M:%S%Z'))).ctime()
		return s[:-4] + self.__tz + s[-5:]

	# Get paginated results when the Registry is too large
	def __get_paginated(self, s):
		elements = []
		while True:
			url = self.__c.get_headers('link')
			if not url:
				break
			m = re.match('</v2/(.*)>; rel="next"', url)
			url = m.group(1)
			data = self.__get(url)
			elements += data[s]
		return	elements

	def get_repositories(self):
		data = self.__get("_catalog")
		repositories = data['repositories'] + self.__get_paginated('repositories')
		return repositories

	def get_tags(self, repo):
		data = self.__get(repo + "/tags/list")
		tags = data['tags'] + self.__get_paginated('tags')
		tags.sort()
		return tags

	def get_manifest(self, repo, tag, version):
		assert version in (1, 2)
		image = repo + ":" + tag
		try:
			manifest = self.__cached_manifest[image][version]
			if manifest:
				return manifest
		except	KeyError:
			self.__cached_manifest = { image: ['', '', ''] }
		data = self.__get(repo + "/manifests/" + tag, ["Accept: application/vnd.docker.distribution.manifest.v%d+json" % (version)])
		self.__cached_manifest[image][version] = data
		return data

	def get_image_info(self, repo, tag):
		info = {}
		manifest = self.get_manifest(repo, tag, 1)
		data = json.loads(manifest['history'][0]['v1Compatibility'])
		for key in ('architecture', 'docker_version', 'os'):
			info[key.title()] = data[key]
		info['Created'] = self.__parse_date(data['created'])
		for key in ('Cmd', 'Entrypoint', 'Env', 'ExposedPorts', 'Labels', 'OnBuild', 'User', 'Volumes', 'WorkingDir'):
			info[key] = data['config'].get(key)
		# Before Docker 1.9.0, ID's were not digests but random bytes
		if info['Docker_Version'] and int(info['Docker_Version'].replace('.', '')) >= 190:
			manifest = self.get_manifest(repo, tag, 2)
			info['Digest'] = manifest['config']['digest'].replace('sha256:', '')
		else:
			info['Digest'] = "-"
		return	info

	def get_image_history(self, repo, tag):
		history = []
		manifest = self.get_manifest(repo, tag, 1)
		prefix = '/bin/sh -c #(nop)'
		n = len(prefix)
		for i in range(len(manifest['history']) - 1, -1, -1):
			data = json.loads(manifest['history'][i]['v1Compatibility'])
			data = " ".join(data['container_config']['Cmd'])
			if data.startswith(prefix):
				data = data[n:].lstrip()
			history += [data]
		return	history

	def get_image_size(self, repo, tag):
		size = 0
		manifest = self.get_manifest(repo, tag, 2)
		for i in range(0, len(manifest['layers'])):
			size += manifest['layers'][i]['size']
		return	size

def main():
	parser = argparse.ArgumentParser(usage=usage, add_help=False)
	parser.add_argument('-c', '--cert')
	parser.add_argument('-k', '--key')
	parser.add_argument('-p', '--pass')
	parser.add_argument('-u', '--user')
	parser.add_argument('-h', '--help', action='store_true')
	parser.add_argument('-v', '--verbose', action='count')
	parser.add_argument('-V', '--version', action='store_true')
	parser.add_argument('image', nargs='?')
	args = parser.parse_args()

	if args.help:
		print('usage: ' + usage)
		sys.exit(0)
	elif args.version:
		print(sys.argv[0] + " " + version + " " + pycurl.version)
		sys.exit(0)
	elif not args.image:
		print('usage: ' + usage, file=sys.stderr)
		sys.exit(1)

	m = re.search('^((?:https?://)?[^:/]+(?::\d+)?)/*(.*)', args.image)
	try:
		registry, args.image = m.group(1), m.group(2)
	except	AttributeError:
		print('usage: ' + usage, file=sys.stderr)
		sys.exit(1)

	reg = DockerRegistryV2(registry, **vars(args))

	# Print information for a specific image
	if args.image:
		def registry_error(error):
			print("ERROR: %s: %s" % ((args.image), error), file=sys.stderr)
			sys.exit(1)

		def pretty_size(size):
			if size < 1024:
				return str(size)
			units = ('','K','M','G','T')
			for n in (4,3,2,1):
				if (size > 1024**n):
					return "%.2f %cB" % ((float(size) / 1024**n), units[n])

		if ':' in args.image:
			repo, tag = args.image.rsplit(':', 1)
		else:
			repo, tag = args.image, "latest"

		try:
			info = reg.get_image_info(repo, tag)
		except	DockerRegistryError as error:
			registry_error(error)

		# Print image info
		keys = list(info)
		keys.sort()
		for key in keys:
			value = info.get(key)
			if not value:
				value = ""
			if type(value) is dict:
				if key == "Labels":
					value = str(json.dumps(value))
				else:
					value = list(value)
			if type(value) is list:
				value = " ".join(value)
			print('%-15s\t%s' % (key.replace('_', ''), value.replace('\t', ' ')))

		# Print compressed image size
		try:
			size = reg.get_image_size(repo, tag)
			print('%-15s\t%s' % ('CompressedSize', pretty_size(size)))
		except  DockerRegistryError as error:
			registry_error(error)

		# Print image history
		try:
			history = reg.get_image_history(repo, tag)
		except	DockerRegistryError as error:
			registry_error(error)
		for i, layer in zip(range(1, len(history)), history):
			print('%-15s\t%s' % ('History[' + str(i) + ']', layer.replace('\t', ' ')))
		sys.exit(0)

	# Print information on all images

	try:	# Python 3
		columns = os.get_terminal_size().columns
	except:	# Unix only
		columns = int(subprocess.check_output(['/bin/stty', 'size']).split()[1])
	cols = int(columns/3)

	print("%-*s\t%-12s\t%-30s\t\t%s" % (cols, "Image", "Id", "Created on", "Docker version"))

	for repo in reg.get_repositories():
		try:
			tags = reg.get_tags(repo)
		except	DockerRegistryError as error:
			print("%-*s\tERROR: %s" % (cols, repo, error))
			continue
		for tag in tags:
			try:
				info = reg.get_image_info(repo, tag)
			except	DockerRegistryError as error:
				print("%-*s\tERROR: %s" % (cols, repo + ":" + tag, error))
			else:
				print("%-*s\t%-12s\t%s\t\t%s" % (cols, repo + ":" + tag,
					info['Digest'][0:12], info['Created'], info['Docker_Version']))

if __name__ == "__main__":
	try:
		main()
	except	KeyboardInterrupt:
		sys.exit(1)

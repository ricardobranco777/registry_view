#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API with PyCurl
#
# Additional support for AWS EC2 Container Registry with Boto3 (pip install boto3)
# See https://github.com/boto/boto3 for configuration details
#
# Reference: https://github.com/docker/distribution/blob/master/docs/spec/api.md
#
# v1.14.1 by Ricardo Branco
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
except	ImportError:
	from urllib import urlencode

try:
	from io import BytesIO
except	ImportError:
	from StringIO import StringIO as BytesIO

if sys.version_info[0] > 2:
	import shutil
else:
	import subprocess
	input = raw_input

progname = os.path.basename(sys.argv[0])
version = "1.14.1"

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
		# Ignore SSL info types
		if not curl_prefix.get(t):
			return
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

	def get(self, url, headers=None, auth=None):
		if headers is None:
			headers = []
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

# Reference:
# https://boto3.readthedocs.io/en/latest/reference/services/ecr.html
class DockerRegistryECR:
	__cached_info = { '': {} }

	def __init__(self, registry):
		try:
			import boto3
		except	ImportError:
			print("WARNING: Install the latest Python boto3 library to AWS ECR. Use: pip install boto3", file=sys.stderr)
			raise ImportError
		self.__c = boto3.client('ecr')
		m = re.search("^(?:https?://)?([0-9]{12})\.*", registry)
		self.__registryId = m.group(1)

	def get_auth(self):
		auth = self.__c.get_authorization_token(registryIds=[self.__registryId,])
		return auth['authorizationData'][0]['authorizationToken']

	def get_repositories(self):
		repositories = []
		paginator = self.__c.get_paginator('describe_repositories')
		for response in paginator.paginate(registryId=self.__registryId):
			repositories += [item['repositoryName'] for item in response['repositories']]
		return	repositories

	def get_tags(self, repo):
		tags = []
		self.__cached_info = { repo: {} }
		image_filter = {'tagStatus': 'TAGGED'}
		paginator = self.__c.get_paginator('describe_images')
		for response in paginator.paginate(registryId=self.__registryId, repositoryName=repo, filter=image_filter):
			for item in response['imageDetails']:
				tags += item['imageTags']
				for tag in item['imageTags']:
					self.__cached_info[repo][tag] = { 'Digest': item['imageDigest'],
									 'CompressedSize': item['imageSizeInBytes'] }
		return	tags

	def get_image_info(self, repo, tag):
		try:
			return self.__cached_info[repo][tag]
		except	KeyError:
			pass
		info = {}
		data = self.__c.describe_images(registryId=self.__registryId, repositoryName=repo, imageIds=[{'imageTag': tag}])
		data = data['imageDetails'][0]
		info['Digest'] = data['imageDigest']
		info['CompressedSize'] = data['imageSizeInBytes']
		return info

	def get_manifest(self, repo, tag):
		data = self.__c.batch_get_image(registryId=self.__registryId, repositoryName=repo, imageIds=[{'imageTag': tag}])
		return json.loads(data['images'][0]['imageManifest'])

class DockerRegistryError(Exception): pass

class DockerRegistryV2:
	__tz = time.strftime('%Z')
	__cached_manifest = {}
	__basic_auth = ""
	__headers = []
	__aws_ecr = None

	def __init__(self, registry, **args):
		self.__c = Curl(**args)
		self.__registry = registry
		# Assume https:// by default
		if not re.match("https?://", self.__registry):
			self.__registry = "https://" + self.__registry
		# Check for AWS EC2 Container Registry
		if re.match("(?:https?://)?[0-9]{12}\.dkr\.ecr\.[a-z0-9]+[a-z0-9-]*\.amazonaws\.com(?::\d+)?$", self.__registry):
			try:
				self.__aws_ecr = DockerRegistryECR(self.__registry)
				return
			except	ImportError:
				if not args['user']:
					print('ERROR: Use the -u option with the credentials obtained from "aws ecr get-login"', file=sys.stderr)
					sys.exit(1)
		# Set credentials if specified or set in ~/.docker/config.json
		if args['user']:
			if not ':' in args['user']:
				args['user'] += ":" + getpass("Password: ")
		if args['user']:
			self.__basic_auth = str(base64.b64encode(args['user'].encode()).decode('ascii'))
		else:
			self.__basic_auth = self.__get_creds()
		# Check Registry v2
		self.__check_registry()

	def __auth_basic(self):
		if not self.__basic_auth:
			userpass = input('Username: ') + ":" + getpass('Password: ')
			self.__basic_auth = str(base64.b64encode(userpass.encode()).decode('ascii'))
		return ['Authorization: Basic ' + self.__basic_auth]

	def __auth_token(self, response_header, use_post=True):
		m = re.match('Bearer realm="([^"]+)".*', response_header)
		url = m.group(1)
		fields = {k: v for k in ("service", "scope", "account")
				for v in re.findall('Bearer realm="(?:[^"]+)".*,%s="([^"]+)"' % (k), response_header) if v}
		fields = urlencode(fields)
		if use_post:
			token = json.loads(self.__c.post(url, fields, auth=self.__auth_basic()))['token']
		else:
			url += '?' + fields
			token = json.loads(self.__c.get(url, auth=self.__auth_basic()))['token']
		return ['Authorization: Bearer ' + token]

	def __get(self, url, headers=None):
		if headers is None:
			headers = []
		tries = 1
		while True:
			body = self.__c.get(self.__registry + "/v2/" + url, self.__headers + headers)
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
				if not self.__headers and self.__basic_auth and tries == 1:
					self.__headers = self.__auth_basic()
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
		body = self.__get("")
		if body == {} or body == "":
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
					break
			except	KeyError:
				pass
		f.close()
		return auth

	# Convert date/time string in ISO-6801 format to date(1)
	def __parse_date(self, ts):
		s = datetime.fromtimestamp(timegm(time.strptime(re.sub("\.\d+Z$", "GMT", ts), '%Y-%m-%dT%H:%M:%S%Z'))).ctime()
		return s[:-4] + self.__tz + s[-5:]

	def __pretty_size(self, size):
		if not size:
			return ""
		if size < 1024:
			return str(size)
		units = ('','K','M','G','T')
		for n in (4,3,2,1):
			if (size > 1024**n):
				return "%.2f %cB" % ((float(size) / 1024**n), units[n])

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
		if self.__aws_ecr:
			repositories = self.__aws_ecr.get_repositories()
		else:
			data = self.__get("_catalog")
			repositories = data['repositories'] + self.__get_paginated('repositories')
		repositories.sort()
		return	repositories

	def get_tags(self, repo):
		if self.__aws_ecr:
			tags = self.__aws_ecr.get_tags(repo)
		else:
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
		if self.__aws_ecr:
			assert version == 1
			self.__cached_manifest[image][version] = self.__aws_ecr.get_manifest(repo, tag)
		else:
			headers = ["Accept: application/vnd.docker.distribution.manifest.v%d+json" % (version)]
			self.__cached_manifest[image][version] = self.__get(repo + "/manifests/" + tag, headers=headers)
		return	self.__cached_manifest[image][version]

	def get_image_info(self, repo, tag):
		info = {}
		manifest = self.get_manifest(repo, tag, 1)
		data = json.loads(manifest['history'][0]['v1Compatibility'])
		info.update({key.title(): data[key] for key in ('architecture', 'docker_version', 'os')})
		info['Created'] = self.__parse_date(data['created'])
		info.update({key: data['config'][key]
			for key in ('Cmd', 'Entrypoint', 'Env', 'ExposedPorts', 'Labels', 'OnBuild', 'User', 'Volumes', 'WorkingDir')
				if data['config'].get(key)})
		# Before Docker 1.9.0, ID's were not digests but random bytes
		info['Digest'] = "-"
		if self.__aws_ecr:
			info.update(self.__aws_ecr.get_image_info(repo, tag))
		elif info['Docker_Version'] and int(info['Docker_Version'].replace('.', '')) >= 190:
			manifest = self.get_manifest(repo, tag, 2)
			try:
				info['Digest'] = manifest['config']['digest']
			except	KeyError:
				pass
			# Calculate compressed size
			info['CompressedSize'] = sum((item['size'] for item in manifest['layers']))
		info['Digest'] = info['Digest'].replace('sha256:', '')
		info['CompressedSize'] = self.__pretty_size(info.get('CompressedSize'))
		return	info

	def get_image_history(self, repo, tag):
		history = []
		manifest = self.get_manifest(repo, tag, 1)
		prefix = '/bin/sh -c #(nop)'
		history = [" ".join(json.loads(item['v1Compatibility'])['container_config']['Cmd']).replace(prefix, "").lstrip()
				for item in reversed(manifest['history'])]
		return	history

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
			value = info[key]
			if type(value) is dict:
				if key == "Labels":
					value = str(json.dumps(value))
				else:
					value = list(value)
			if type(value) is list:
				value = " ".join(value)
			print('%-15s\t%s' % (key.replace('_', ''), value.replace('\t', ' ')))

		# Print image history
		try:
			history = reg.get_image_history(repo, tag)
		except	DockerRegistryError as error:
			registry_error(error)
		for i, layer in enumerate(history, 1):
			print('%-15s\t%s' % ('History[' + str(i) + ']', layer.replace('\t', ' ')))
		sys.exit(0)

	# Print information on all images

	try:	# Python 3
		columns = shutil.get_terminal_size(fallback=(158, 40)).columns
	except:	# Unix only
		columns = int(subprocess.check_output(['/bin/stty', 'size']).split()[1])
	cols = int(columns/3)

	print("%-*s\t%-12s\t%-30s\t%s\t%s" % (cols, "Image", "Id", "Created on", "Docker", "Compressed Size"))

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
				print("%-*s\t%-12s\t%s\t%s\t%s" % (cols, repo + ":" + tag,
					info['Digest'][0:12], info['Created'], info['Docker_Version'], info['CompressedSize']))

if __name__ == "__main__":
	try:
		main()
	except	KeyboardInterrupt:
		sys.exit(1)

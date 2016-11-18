#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API via curl
#
# v1.8 by Ricardo Branco
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
	def __init__(self, **opts):
		self.c = pycurl.Curl()
		curlopts = [('cert', pycurl.SSLCERT), ('key', pycurl.SSLKEY), ('verbose', pycurl.VERBOSE)]
		if hasattr(pycurl, 'KEYPASSWD'):
			curlopts.append(['pass', pycurl.KEYPASSWD])	# Option added to PyCurl 7.21.5
		else:
			curlopts.append(['pass', pycurl.SSLCERTPASSWD])
		for opt, curlopt in curlopts:
			if opts[opt]: self.c.setopt(curlopt, opts[opt])
		self.c.setopt(pycurl.SSL_VERIFYPEER, 0)
		if opts['verbose'] and opts['verbose'] > 1:
			self.c.setopt(pycurl.DEBUGFUNCTION, self.__debug_function)

	def __del__(self):
		if self.c: self.c.close()

	def __debug_function(self, t, m):
		debug_str = { pycurl.INFOTYPE_TEXT: '* ', pycurl.INFOTYPE_HEADER_IN: '< ', pycurl.INFOTYPE_HEADER_OUT: '> ',
			pycurl.INFOTYPE_DATA_IN: '', pycurl.INFOTYPE_DATA_OUT: '' }

		m = m.decode('iso-8859-1').rstrip()
		if t == pycurl.INFOTYPE_HEADER_OUT:
			m = m.replace('\n', '\n' + debug_str.get(t))
		print(debug_str.get(t) + m)

	# Adapted from https://github.com/pycurl/pycurl/blob/master/examples/quickstart/response_headers.py
	def __header_function(self, header_line):
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
		self.__headers[name] = value

	def get(self, url, headers=[]):
		buf = BytesIO()
		self.__headers = {}
		self.c.setopt(pycurl.URL, url)
		self.c.setopt(pycurl.WRITEDATA, buf)
		self.c.setopt(pycurl.HTTPHEADER, headers)
		self.c.setopt(pycurl.HEADERFUNCTION, self.__header_function)
		try:
			self.c.perform()
		except	pycurl.error as err:
			print(self.c.errstr(), file=sys.stderr)
			sys.exit(err.args[0])
		body = buf.getvalue()
		buf.close()
		return body.decode(self.get_charset())

	def get_headers(self):
		return self.__headers

	def get_charset(self):
		try:
			n = self.__headers['Content-Type'].find(' charset=')
		except	KeyError:
			n = -1
		if n == -1:
			return 'iso-8859-1'
		else:
			n += len(' charset=')
		return self.__headers['Content-Type'][n:].split(';')[0]

	def get_http_code(self):
		return self.c.getinfo(pycurl.HTTP_CODE)

class DockerRegistryError(Exception): pass

class DockerRegistryV2:
	__tz = time.strftime('%Z')

	def __init__(self, registry, **args):
		self.__c = Curl(**args)
		self.__registry = registry
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

	def __get(self, url, headers=[]):
		return self.__c.get(self.__registry + "/v2/" + url, headers)

	def __check_registry(self):
		if self.__get("") == "{}":
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

	# Convert date/time string in ISO-6801 format to date(1)
	def __parse_date(self, ts):
		s = datetime.fromtimestamp(timegm(time.strptime(re.sub("\.\d+Z$", "GMT", ts), '%Y-%m-%dT%H:%M:%S%Z'))).ctime()
		return s[:-4] + self.__tz + s[-5:]


	def get_repositories(self):
		data = json.loads(self.__get("_catalog"))
		data['repositories'].sort()
		return data['repositories']

	def get_tags(self, repo):
		info = self.__get(repo + "/tags/list")
		data = json.loads(info)
		if info.startswith('{"errors":'):
			raise DockerRegistryError(data['errors'][0]['message'])
		data['tags'].sort()
		return data['tags']

	def get_manifest(self, repo, tag, version):
		assert version in (1, 2)
		info = self.__get(repo + "/manifests/" + tag,
			["Accept: application/vnd.docker.distribution.manifest.v" + str(version) + "+json"])
		data = json.loads(info)
		if info.startswith('{"errors":'):
			raise DockerRegistryError(data['errors'][0]['message'])
		return data

	def get_image_info(self, repo, tag):
		self.__info = {}
		manifest = self.get_manifest(repo, tag, 1)
		data = json.loads(manifest['history'][0]['v1Compatibility'])
		for key in ('architecture', 'docker_version', 'os'):
			self.__info[key.title()] = data[key]
		self.__info['Created'] = self.__parse_date(data['created'])
		for key in ('Cmd', 'Entrypoint', 'Env', 'ExposedPorts', 'Labels', 'OnBuild', 'User', 'Volumes', 'WorkingDir'):
			self.__info[key] = data['config'][key]
		# Before Docker 1.9.0, ID's were not digests but random bytes
		if self.__info['Docker_Version'] and int(self.__info['Docker_Version'].replace('.', '')) > 190:
			manifest = self.get_manifest(repo, tag, 2)
			self.__info['Digest'] = manifest['config']['digest'].replace('sha256:', '')
		else:
			self.__info['Digest'] = "-"
		return	self.__info


def main():
	usage = os.path.basename(sys.argv[0]) + """ [OPTIONS]... REGISTRY[:PORT][/REPOSITORY[:TAG]]
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
	parser.add_argument('image', nargs='?')
	args = parser.parse_args()

	if args.help:
		sys.exit('usage: ' + usage)
	elif not args.image:
		print('usage: ' + usage, file=sys.stderr)
		sys.exit(1)

	m = re.search('^((?:https?://)?[^:/]+(?::\d+)?)/*(.*)', args.image)
	registry, args.image = m.group(1), m.group(2)

	reg = DockerRegistryV2(registry, **vars(args))

	if args.image:
		if ':' in args.image:
			repo, tag = args.image.rsplit(':', 1)
		else:
			repo, tag = args.image, "latest"
		try:
			info = reg.get_image_info(repo, tag)
		except	DockerRegistryError as error:
			print("ERROR: " + args.image + ": " + str(error), file=sys.stderr)
			sys.exit(1)
		keys = list(info)
		keys.sort()
		for key in keys:
			value = info.get(key)
			if not value:
				value = ""
			if type(value) is dict:
				if key == "Labels":
					#value = ' '.join('{}={}'.format(k, value[k]) for k in value)
					value = ' '.join('%s=%s' % (k, value[k]) for k in value)
				else:
					value = list(value)
			if type(value) is list:
				value = " ".join(value)
			print('%-15s\t%s' % (key.replace('_', ''), value.replace('\t', ' ')))
		sys.exit(0)

	try:	# Python 3
		columns = os.get_terminal_size().columns
	except:	# Unix only
		columns = int(subprocess.check_output(['stty', 'size']).split()[1])
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

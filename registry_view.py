#!/usr/bin/env python3
#
# Script to visualize the contents of a Docker Registry v2 using the API with PyCurl
#
# Additional support for AWS EC2 Container Registry with Boto3 (pip install boto3)
# See https://github.com/boto/boto3 for configuration details
#
# Reference: https://github.com/docker/distribution/blob/master/docs/spec/api.md
#
# v1.24.2 by Ricardo Branco
#
# MIT License

import argparse
import base64
import json
import os
import re
import sys

from calendar import timegm
from time import localtime, strptime, strftime
from getpass import getpass
from urllib.parse import urlencode
from io import BytesIO

try:
    import pycurl
except ImportError:
    print('ERROR: Please install PyCurl', file=sys.stderr)
    sys.exit(1)

PROGNAME = os.path.basename(sys.argv[0])
VERSION = "1.24.2"

USAGE = "\rUsage: " + PROGNAME + """ [OPTIONS]... REGISTRY[:PORT][/REPOSITORY[:TAG]]
Options:
        -c, --cert CERT         Client certificate file name
        -k, --key  KEY          Client private key file name
        -p, --pass PASS         Pass phrase for the private key
        -u, --user USER[:PASS]  Server user and password (for HTTP Basic authentication)
        --digests               Show digests
        --no-trunc              Don't truncate output
        -r, --reverse           Reverse order with the -s & -t options
        -s, --size              Sort images by size with the largest ones coming first
        -t, --time              Sort images by time with the newest ones coming first
        -v, --verbose           Be verbose. May be specified multiple times
        -V, --version           Show version string and quit

Note: Default PORT is 443. You must prepend "http://" to REGISTRY if running on plain HTTP.
"""

ARGS = None
COLS = 0

os.environ['LC_ALL'] = 'C.UTF-8'


# Debug function used to mimic curl's debug output
def debug_function(infotype, message):
    curl_prefix = {
        pycurl.INFOTYPE_TEXT: '* ',
        pycurl.INFOTYPE_HEADER_IN: '< ',
        pycurl.INFOTYPE_HEADER_OUT: '> ',
        pycurl.INFOTYPE_DATA_IN: '',
        pycurl.INFOTYPE_DATA_OUT: ''
    }
    # Ignore SSL info types
    if infotype not in curl_prefix:
        return
    # Strip trailing whitespace
    message = message.decode('iso-8859-1').rstrip()
    print(curl_prefix[infotype] + message)


def error(msg, bye=True):
    '''Prints an error message and optionally exit with a status code of 1'''
    print("ERROR: " + str(msg), file=sys.stderr)
    if bye:
        sys.exit(1)


class Curl:
    """This class encapsulates PyCurl operations"""

    def __init__(self, **opts):
        """Initializes a pycurl handle"""
        self.c = pycurl.Curl()
        curlopts = [
            ('cert', pycurl.SSLCERT),
            ('key', pycurl.SSLKEY),
            ('verbose', pycurl.VERBOSE)
        ]
        # Compatibility with older versions of PyCurl
        if hasattr(pycurl, 'KEYPASSWD'):
            curlopts += [('pass', pycurl.KEYPASSWD)]
        elif hasattr(pycurl, 'SSLKEYPASSWD'):
            curlopts += [('pass', pycurl.SSLKEYPASSWD)]
        else:
            curlopts += [('pass', pycurl.SSLCERTPASSWD)]
        for opt, curlopt in curlopts:
            if opts[opt] is not None:
                self.c.setopt(curlopt, opts[opt])
        self.c.setopt(pycurl.SSL_VERIFYPEER, 1)
        if opts['verbose'] is not None and opts['verbose'] > 1:
            self.c.setopt(pycurl.DEBUGFUNCTION, debug_function)
        self.c.setopt(pycurl.HEADERFUNCTION, self._header_function)
        self.c.setopt(
            pycurl.USERAGENT, '%s/%s %s' % (PROGNAME, VERSION, pycurl.version)
        )
        self.buf = BytesIO()
        try:
            self.c.setopt(pycurl.WRITE, self.buf)
        except AttributeError:
            self.c.setopt(pycurl.WRITEFUNCTION, self.buf.write)

    def __del__(self):
        """Closes the pycurl handle"""
        self.buf.close()
        self.c.close()

    # Adapted from:
    # https://github.com/pycurl/pycurl/blob/master/examples/quickstart/response_headers.py
    def _header_function(self, header_line):
        """Gets the HTTP headers from a response"""
        # HTTP standard specifies that headers are encoded in iso-8859-1
        header_line = header_line.decode('iso-8859-1')
        # Header lines include the first status line (HTTP/1.x ...)
        if ':' not in header_line:
            if 'HTTP_STATUS' not in self.headers:
                self.headers['HTTP_STATUS'] = header_line.strip()
            return
        # Break the header line into header name and value.
        name, value = header_line.split(':', 1)
        # Remove whitespace that may be present.
        self.headers[name.strip().lower()] = value.strip()

    def get(self, url, headers=None, auth=None):
        """Makes the HTTP GET request with optional headers.
        The auth parameter must begin with 'Authorization: '"""
        if headers is None:
            headers = []
        self.headers = {}
        self.buf.seek(0)
        self.buf.truncate()
        self.c.setopt(pycurl.URL, url)
        self.c.setopt(pycurl.HTTPGET, 1)
        self.c.setopt(pycurl.HTTPHEADER, headers)
        if auth is not None:
            self.c.setopt(pycurl.HTTPHEADER, auth)
        try:
            self.c.perform()
        except pycurl.error as err:
            print(self.c.errstr(), file=sys.stderr)
            sys.exit(err.args[0])
        body = self.buf.getvalue()
        return body.decode('utf-8')

    def post(self, url, post_data, auth=None):
        """Makes the HTTP POST request.
        The auth parameter must begin with 'Authorization: '"""
        self.buf.seek(0)
        self.buf.truncate()
        self.c.setopt(pycurl.URL, url)
        self.c.setopt(pycurl.POST, 1)
        self.c.setopt(pycurl.POSTFIELDS, post_data)
        if auth is not None:
            self.c.setopt(pycurl.HTTPHEADER, auth)
        try:
            self.c.perform()
        except pycurl.error as err:
            print(self.c.errstr(), file=sys.stderr)
            sys.exit(err.args[0])
        body = self.buf.getvalue()
        return body.decode('utf-8')

    def get_headers(self, key):
        """Get a specific header line"""
        return self.headers.get(key)

    def get_http_code(self):
        """Get the HTTP response code for the last operation"""
        return self.c.getinfo(pycurl.HTTP_CODE)


# Reference:
# https://boto3.readthedocs.io/en/latest/reference/services/ecr.html
class DockerRegistryECR:
    """This class encapsulates Boto3 operations to get information from an EC2 Container Registry"""

    _cache = {'': {}}

    def __init__(self, registry):
        """Gets the boto3 handle"""
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError:
            error("Please install boto3")
        self.BotoCoreError, self.ClientError = BotoCoreError, ClientError
        self._c = boto3.client('ecr')
        self._registryId = re.findall(r"^(?:https?://)?(.*?)\.", registry)[0]

    def get_repositories(self):
        """Returns a list of repositories"""
        paginator = self._c.get_paginator('describe_repositories')
        try:
            repositories = [
                item['repositoryName']
                for page in paginator.paginate(registryId=self._registryId)
                for item in page['repositories']
            ]
        except (self.BotoCoreError, self.ClientError) as err:
            error(err)
        return repositories

    def get_tags(self, repo):
        """Returns a list of tags for the specified repository"""
        tags = []
        self._cache = {repo: {}}
        keys = (
            ('Digest', 'imageDigest'),
            ('CompressedSize', 'imageSizeInBytes')
        )
        image_filter = {'tagStatus': 'TAGGED'}
        paginator = self._c.get_paginator('describe_images')
        for page in paginator.paginate(
                registryId=self._registryId,
                repositoryName=repo,
                filter=image_filter
        ):
            for item in page['imageDetails']:
                tags += item['imageTags']
                for tag in item['imageTags']:
                    self._cache[repo][tag] = {
                        k1: item[k2] for (k1, k2) in keys
                    }
        return tags

    def get_image_info(self, repo, tag, digest=None):
        """Returns a dictionary with image info such as Digest and CompressedSize"""
        try:
            return self._cache[repo][tag]
        except KeyError:
            pass
        if digest is None:
            imageIds = [{'imageTag': tag}]
        else:
            imageIds = [{'imageDigest': digest}]
        try:
            data = self._c.describe_images(
                registryId=self._registryId,
                repositoryName=repo,
                imageIds=imageIds
            )
        except (self.BotoCoreError, self.ClientError) as err:
            raise DockerRegistryError(err)
        data = data['imageDetails'][0]
        keys = (('Digest', 'imageDigest'),
                ('CompressedSize', 'imageSizeInBytes'))
        return {k1: data[k2] for (k1, k2) in keys}

    def get_manifest(self, repo, tag, version, digest=None):
        """Returns the image manifest as a dictionary"""
        if digest is None:
            imageIds = [{'imageTag': tag}]
        else:
            imageIds = [{'imageDigest': digest}]
        data = self._c.batch_get_image(
            registryId=self._registryId,
            repositoryName=repo,
            imageIds=imageIds,
            acceptedMediaTypes=[
                "application/vnd.docker.distribution.manifest.v%d+json" % version
            ]
        )
        return json.loads(data['images'][0]['imageManifest'])


class DockerRegistryError(Exception):
    """This class is used to raise Docker Registry errors"""
    pass


class DockerRegistryV2:
    """This class encapsulates operations to get information from a Docker Registry v2"""

    _aws_ecr = None
    _basic_auth = ""
    _headers = []  # XXX: Document

    def __init__(self, registry, **args):
        """Get a Curl handle and checks the type and availability of the Registry"""
        self._c = Curl(**args)
        self._registry = registry
        # Assume https:// by default
        if not re.match("https?://", self._registry):
            self._registry = "https://" + self._registry
        # Check for AWS EC2 Container Registry
        if re.match(
                r"(?:https?://)?.*?\.amazonaws\.com(?::[0-9]+)?$",
                self._registry
        ):
            self._aws_ecr = DockerRegistryECR(self._registry)
            return
        # Set credentials if specified or set in ~/.docker/config.json
        if args['user'] is not None and ':' not in args['user']:
            args['user'] += ":" + getpass("Password: ")
        if args['user'] is not None:
            self._basic_auth = str(base64.b64encode(args['user'].encode()).decode('ascii'))
        else:
            self._basic_auth = self._get_creds()
        # Check Registry v2
        self._check_registry()

    def _auth_basic(self):
        """Returns the 'Authorization' header for HTTP Basic Authentication"""
        if not self._basic_auth:
            userpass = input('Username: ') + ":" + getpass('Password: ')
            self._basic_auth = str(base64.b64encode(userpass.encode()).decode('ascii'))
        return ['Authorization: Basic ' + self._basic_auth]

    # Reference: https://docs.docker.com/registry/spec/auth/
    def _auth_token(self, response_header, use_post=True):
        """Returns the token from the response_header"""
        fields = {k: v for (k, v) in re.findall(',?([^=]+)="([^"]+)"', response_header)}
        url = fields['Bearer realm']
        del fields['Bearer realm']
        fields = urlencode(fields)
        if use_post:
            try:
                token = json.loads(self._c.post(url, fields, auth=self._auth_basic()))['token']
            except KeyError:
                pass
            if self._c.get_http_code() == 405:
                use_post = False
        if not use_post:
            url += '?' + fields
            token = json.loads(self._c.get(url, auth=self._auth_basic()))['token']
        return ['Authorization: Bearer ' + token]

    def _get(self, url, headers=None):
        """Gets the specified url within the Docker Registry with optional headers"""
        if headers is None:
            headers = []
        tries = 1
        while True:
            body = self._c.get(self._registry + "/v2/" + url, self._headers + headers)
            http_code = self._c.get_http_code()
            if http_code == 401 and tries > 0:
                headers = headers[:]
                auth_method = self._c.get_headers('www-authenticate')
                if auth_method is None or auth_method.startswith('Basic '):
                    headers += self._auth_basic()
                elif auth_method.startswith('Bearer '):
                    headers += self._auth_token(auth_method)
                else:
                    error("Unsupported authentication method: " + auth_method)
            else:
                if not self._headers and self._basic_auth and tries == 1:
                    self._headers = self._auth_basic()
                try:
                    data = json.loads(body)
                except ValueError:
                    if http_code == 200:
                        return body
                    raise DockerRegistryError(body.strip())
                if 'errors' in data:
                    if 'message' in data['errors'][0]:
                        raise DockerRegistryError(data['errors'][0]['message'])
                    else:
                        raise DockerRegistryError(data['errors'][0]['code'])
                else:
                    return data
            tries -= 1

    def _check_registry(self):
        """Checks for a valid Docker Registry"""
        body = self._get("")
        if not body:
            return
        http_code = self._c.get_http_code()
        if http_code == 404:
            err = 'Invalid v2 Docker Registry: ' + self._registry
        elif not self._c.get_headers('HTTP_STATUS'):
            err = "Invalid HTTP server"
        error(err)

    def _get_creds(self):
        """Gets the credentials from ~/.docker/config.json"""
        config_file = ""
        if os.getenv("DOCKER_CONFIG") is not None:
            config_file = os.path.join(os.getenv("DOCKER_CONFIG"), "config.json")
        else:
            config_file = os.path.expanduser(os.path.join("~", ".docker", "config.json"))
            if not os.path.exists(config_file):
                config_file = os.path.expanduser(os.path.join("~", ".dockercfg"))
        if not os.path.exists(config_file):
            return None
        with open(os.path.expanduser(config_file), "r") as file:
            config = json.load(file)
        try:
            return config['auths'][re.sub("^https?://", "", self._registry)]['auth']
        except KeyError:
            pass
        return None

    def _get_paginated(self, string):
        """Get paginated results when the Registry is too large"""
        elements = []
        while True:
            url = self._c.get_headers('link')
            if url is None:
                break
            url = re.findall('</v2/(.*)>; rel="next"', url)[0]
            data = self._get(url)
            elements += data[string]
        return elements

    def get_repositories(self):
        """Returns a list of repositories"""
        if self._aws_ecr is not None:
            return self._aws_ecr.get_repositories()
        data = self._get("_catalog")
        repos = data['repositories'] + self._get_paginated('repositories')
        repos.sort()
        return repos

    def get_tags(self, repo):
        """Returns a list of tags for the specified repository"""
        if self._aws_ecr is not None:
            return self._aws_ecr.get_tags(repo)
        data = self._get(repo + "/tags/list")
        tags = data['tags'] + self._get_paginated('tags')
        tags.sort()
        return tags

    def get_manifest(self, repo, tag, version, digest=None):
        """Returns the image manifest as a dictionary. The schema versions must be 1 or 2"""
        if self._aws_ecr is not None:
            return self._aws_ecr.get_manifest(repo, tag, version, digest)
        headers = []
        if version == 1:
            headers = [
                "Accept: application/vnd.docker.distribution.manifest.v1+json",
                "Accept: application/vnd.docker.distribution.manifest.list.v2+json",
            ]
        else:
            headers += [
                "Accept: application/vnd.docker.distribution.manifest.v2+json"
            ]
        if digest is not None:
            return self._get("%s/manifests/%s" % (repo, digest), headers=headers)
        else:
            return self._get("%s/manifests/%s" % (repo, tag), headers=headers)

    # TODO: Cache result for schema v1 for get_image_history()
    def get_image_info(self, repo, tag, digest=None):
        """Returns a dictionary with image info containing the most interesting items"""
        info = {}
        if self._aws_ecr is not None:
            info.update(self._aws_ecr.get_image_info(repo, tag, digest))
        manifest = self.get_manifest(repo, tag, 1, digest)
        if manifest['schemaVersion'] == 1:
            data = json.loads(manifest['history'][0]['v1Compatibility'])
            info.update({
                key.title(): data[key]
                for key in ('architecture', 'created', 'docker_version', 'os')
            })
            keys = (
                'Cmd', 'Entrypoint', 'Env', 'ExposedPorts',
                'Healthcheck', 'Labels', 'OnBuild', 'Shell',
                'StopSignal', 'User', 'Volumes', 'WorkingDir'
            )
            info.update({key: data['config'].get(key, "") for key in keys})
        if self._aws_ecr is not None:
            return info
        if manifest['schemaVersion'] != 2:
            manifest = self.get_manifest(repo, tag, 2, digest)
        if manifest['mediaType'] == "application/vnd.docker.distribution.manifest.v2+json":
            # Single manifest
            info['Digest'] = self._c.get_headers('docker-content-digest')
            info['Id'] = manifest['config']['digest']
        elif manifest['mediaType'] == "application/vnd.docker.distribution.manifest.list.v2+json":
            # Fat manifest (multi-arch)
            info = []
            for i, manifest in enumerate(manifest['manifests']):
                info.append(
                    self.get_image_info(
                        repo,
                        tag=None,
                        digest=manifest['digest'])
                )
                info[i]['Architecture'] = manifest['platform']['architecture']
                info[i]['Os'] = manifest['platform']['os']
            return info
        else:
            error("Unsupported media type: %s", manifest['mediaType'])
        # Calculate compressed size
        try:
            info['CompressedSize'] = sum(
                [item['size'] for item in manifest['layers']]
            )
        except KeyError:
            pass
        info.update(
            {key: "-" for key in ("Architecture", "Os") if key not in info}
        )
        return info

    def get_image_history(self, repo, tag, digest=None):
        """Returns a list containing the image history (layers)"""
        manifest = self.get_manifest(repo, tag, 1, digest)
        if manifest['schemaVersion'] != 1:
            return []
        return [
            " ".join(json.loads(item['v1Compatibility'])['container_config']['Cmd'])
            for item in reversed(manifest['history'])
        ]


# Converts a size in bytes to a string in KB, MB, GB or TB
def pretty_size(size):
    units = (' ', 'K', 'M', 'G', 'T')
    for i in range(4, -1, -1):
        if size > 1024**i:
            return "%.2f%cB" % (float(size) / 1024**i, units[i])


# Converts date/time string in ISO-8601 format to date(1)
def pretty_date(time_string):
    return strftime(
        "%a %b %d %H:%M:%S %Z %Y",
        localtime(timegm(strptime(re.sub(r"\.\d+Z$", "GMT", time_string),
                                  '%Y-%m-%dT%H:%M:%S%Z')))
    )


# Converts nanoseconds into a string that can be parsed by Go's time.ParseDuration()
def pretty_time(nanoseconds):
    microseconds_ns = 1e3
    milliseconds_ns = 1e3 * microseconds_ns
    seconds_ns = 1e3 * milliseconds_ns
    minutes_ns = 60 * seconds_ns
    hours_ns = 60 * minutes_ns
    nanoseconds = int(nanoseconds)
    if not nanoseconds:
        return "0"
    time_string = ""
    hours = int(nanoseconds / hours_ns)
    if hours:
        time_string += "%dh" % hours
        nanoseconds -= hours * hours_ns
    minutes = int(nanoseconds / minutes_ns)
    if minutes:
        time_string += "%dm" % minutes
        nanoseconds -= minutes * minutes_ns
    seconds = int(nanoseconds / seconds_ns)
    if seconds:
        time_string += "%dm" % seconds
        nanoseconds -= seconds * seconds_ns
    milliseconds = int(nanoseconds / milliseconds_ns)
    if milliseconds:
        time_string += "%dms" % milliseconds
        nanoseconds -= milliseconds * milliseconds_ns
    microseconds = int(nanoseconds / microseconds_ns)
    if microseconds:
        time_string += "%dus" % microseconds
        nanoseconds -= microseconds * microseconds_ns
    if nanoseconds:
        time_string += "%dns" % nanoseconds
    return time_string


# Print image history
def print_history(history, os_):
    if os_ == "windows":
        shell = 'cmd /S /C'
    else:
        shell = '/bin/sh -c'
    for i, layer in enumerate(history, 1):
        # The format of the SHELL command in the manifest is:
        # "/bin/bash -c #(nop)  SHELL [/bin/bash -c]" when 'SHELL ["/bin/bash", "-c"]' is used in the Dockerfile
        match = re.match(r"(.*) #\(nop\)  SHELL \[(.*)\]$", layer)
        if match and len(match.groups()) == 2 and match.group(1) == match.group(2):
            shell = match.group(1)
        layer = re.sub('^' + shell + r' #\(nop\)', "", layer)
        layer = re.sub('^' + shell, "RUN", layer).lstrip()
        if layer.startswith('HEALTHCHECK &{["CMD-SHELL" '):
            cmd, interval, timeout, start, retries = re.findall(
                r'^HEALTHCHECK &{\["CMD-SHELL" "(.*?)"] "(.*?)" "(.*?)" "(.*?)" \'\\x(.*)\'}$',
                layer
            )[0]
            retries = str(int(retries, base=16))
            layer = "HEALTHCHECK"
            if interval != "0s":
                layer += " --interval=" + interval
            if timeout != "0s":
                layer += " --timeout=" + timeout
            if start != "0s":
                layer += " --start-period=" + start
            if retries != "0":
                layer += " --retries=" + retries
            layer += " CMD " + cmd
        elif layer.startswith('HEALTHCHECK &{["NONE"] "'):
            layer = "HEALTHCHECK NONE"
        print('%-15s\t%s' % ('History[' + str(i) + ']', layer))


# Print image info
def print_image_info(reg, repo, tag, info):
    if 'Env' in info:
        # Convert 'PATH=xxx foo=bar' into 'PATH="xxx" foo="bar"'
        info["Env"] = [
            re.sub('([^=]+)=(.*)', r'\1="\2"', env.replace('"', r'\"'))
            for env in info["Env"]
        ]

    keys = list(info)
    for key in sorted(keys):
        value = info[key]
        if isinstance(value, dict):
            if key == "Labels":
                if value:
                    value = str(json.dumps(value))
                else:
                    value = ""
            elif key == "Healthcheck":
                value = ""
                for k in ('Interval', 'Timeout', 'StartPeriod'):
                    if info[key][k]:
                        value += "%s=%s " % (k, pretty_time(info[key][k]))
                if info[key]['Retries']:
                    value += "Retries=%d " % info[key]['Retries']
                value += "Command=" + info[key]['Test'][1]
            else:
                value = list(value)
        if isinstance(value, list):
            if key in ('Env', 'ExposedPorts', 'Volumes'):
                value = " ".join(sorted(value))
            elif value:
                value = "[ '" + "".join("', '".join(_ for _ in value)) + "' ]"
        if value is None or not value:
            value = ""
        print('%-15s\t%s' % (key.replace('_', ''), value))

    # Print image history
    try:
        history = reg.get_image_history(repo, tag, info['Digest'])
    except DockerRegistryError as err:
        error(err)
    print_history(history, info['Os'])


def print_info(info):
    id_ = info['Id']
    if ARGS.no_trunc:
        id_ = id_.replace("sha256:", "")[0:12]
        id_size = 15
    else:
        id_size = 75
    created = info.get('Created')
    created = pretty_date(created) if created else "-"
    size = info.get('CompressedSize')
    size = pretty_size(size) if size else "-"
    if ARGS.digests:
        print("%-*s %-75s%-*s%-30s %-15s %s/%s" % (
            COLS, info['Repo'] + ":" + info['Tag'], info['Digest'],
            id_size, id_, created, size, info['Os'], info['Architecture']))
    else:
        print("%-*s %-*s%-30s %-15s %s/%s" % (
            COLS, info['Repo'] + ":" + info['Tag'],
            id_size, id_, created, size, info['Os'], info['Architecture']))


def main():
    parser = argparse.ArgumentParser(usage=USAGE, add_help=False)
    parser.add_argument('-c', '--cert')
    parser.add_argument('-k', '--key')
    parser.add_argument('-p', '--pass')
    parser.add_argument('-u', '--user')
    parser.add_argument('--digests', action='store_true')
    parser.add_argument('--no-trunc', action='store_false')
    parser.add_argument('-r', '--reverse', action='store_false')
    parser.add_argument('-s', '--size', action='store_true')
    parser.add_argument('-t', '--time', action='store_true')
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('-V', '--version', action='store_true')
    parser.add_argument('image', nargs='?')
    global ARGS
    ARGS = parser.parse_args()

    if ARGS.help:
        print('usage: ' + USAGE)
        sys.exit(0)
    elif ARGS.version:
        print("%s %s %s" % (PROGNAME, VERSION, pycurl.version))
        sys.exit(0)
    elif not ARGS.image:
        print('usage: ' + USAGE, file=sys.stderr)
        sys.exit(1)

    match = re.search('^((?:https?://)?[^:/]+(?::[0-9]+)?)/*(.*)', ARGS.image)
    try:
        registry, ARGS.image = match.group(1), match.group(2)
    except AttributeError:
        print('usage: ' + USAGE, file=sys.stderr)
        sys.exit(1)

    reg = DockerRegistryV2(registry, **vars(ARGS))

    #
    # Print information for a specific image
    #
    if ARGS.image and not ARGS.image.endswith('*'):
        tag = digest = None
        if '@' in ARGS.image:
            repo, digest = ARGS.image.rsplit('@', 1)
        elif ':' in ARGS.image:
            repo, tag = ARGS.image.rsplit(':', 1)
        else:
            repo, tag = ARGS.image, "latest"
        try:
            info = reg.get_image_info(repo, tag, digest)
        except DockerRegistryError as err:
            error(err)
        if not isinstance(info, list):
            info = [info]
        for item in info:
            print_image_info(reg, repo, tag, item)
        sys.exit(0)

    #
    # Print information on all images
    #

    if ARGS.no_trunc:
        id_size = 15
    else:
        id_size = 75

    info = {}
    repos = reg.get_repositories()
    global COLS
    COLS = len(max(repos, key=len)) + 15

    if ARGS.digests:
        print("%-*s %-75s%-*s%-30s %-15s %s" % (
            COLS, "Image", "Digest", id_size, "Id", "Created on",
            "Compressed Size", "Platform"))
    else:
        print("%-*s %-*s%-30s %-15s %s" % (
            COLS, "Image", id_size, "Id", "Created on",
            "Compressed Size", "Platform"))

    glob_repo = ARGS.image.split(':', 1)[0].rstrip('*')
    if ':' in ARGS.image:
        glob_tag = ARGS.image.split(':', 1)[1].rstrip('*')
    else:
        glob_tag = ""
    for repo in repos:
        if ARGS.image and not repo.startswith(glob_repo):
            continue
        try:
            tags = reg.get_tags(repo)
        except DockerRegistryError as err:
            print("%-*s\tERROR: %s" % (COLS, repo, err))
            continue
        if not (ARGS.size or ARGS.time):
            info = {}
        for tag in tags:
            if glob_tag and not tag.startswith(glob_tag):
                continue
            try:
                image_info = reg.get_image_info(repo, tag)
                if not isinstance(image_info, list):
                    image_info = [image_info]
                for item in image_info:
                    key = item['Digest']
                    info[key] = item
                    info[key]['Repo'] = repo
                    info[key]['Tag'] = tag
            except DockerRegistryError as err:
                print("%-*s\tERROR: %s" % (COLS, repo + ":" + tag, err))
                continue
        if ARGS.size or ARGS.time:
            continue
        for image in sorted(
                info,
                key=lambda k: (info[k].get('Created'), k),
                reverse=not ARGS.reverse
        ):
            print_info(info[image])

    # Show output sorted by size or time
    images = []
    if ARGS.size:
        images = sorted(
            info,
            key=lambda k: info[k].get('CompressedSize', 0),
            reverse=ARGS.reverse
        )
    elif ARGS.time:
        images = sorted(
            info,
            key=lambda k: info[k].get('Created', 0),
            reverse=ARGS.reverse
        )
    for image in images:
        print_info(info[image])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

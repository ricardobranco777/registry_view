#!/usr/bin/env python
#
# Script to visualize the contents of a Docker Registry v2 using the API with PyCurl
#
# Additional support for AWS EC2 Container Registry with Boto3 (pip install boto3)
# See https://github.com/boto/boto3 for configuration details
#
# Reference: https://github.com/docker/distribution/blob/master/docs/spec/api.md
#
# v1.16.2 by Ricardo Branco
#
# MIT License

from __future__ import print_function

import argparse, base64, json, os, re, string, sys

from calendar import timegm
from datetime import datetime
from time import localtime, sleep, strptime, strftime
from getpass import getpass

try:
    import pycurl
except ImportError:
    print('ERROR: Please install PyCurl', file=sys.stderr)
    sys.exit(1)

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

PY3 = sys.version_info[0] == 3

if PY3:
    import shutil
else:
    import subprocess
    input = raw_input

progname = os.path.basename(sys.argv[0])
version = "1.16.2"

usage = "\rUsage: " + progname + """ [OPTIONS]... REGISTRY[:PORT][/REPOSITORY[:TAG]]
Options:
        -c, --cert CERT         Client certificate file name
        -k, --key  KEY          Client private key file name
        -p, --pass PASS         Pass phrase for the private key
        -u, --user USER[:PASS]  Server user and password (for HTTP Basic authentication)
        -r, --reverse           Reverse order with the -s & -t options
        -s, --size              Sort images by size with the largest ones coming first
        -t, --time              Sort images by time with the newest ones coming first
        -v, --verbose           Be verbose. May be specified multiple times
        -V, --version           Show version string and quit

Note: Default PORT is 443. You must prepend "http://" to REGISTRY if running on plain HTTP.
"""

os.environ['LC_ALL'] = 'C.UTF-8'


class Curl:
    """This class encapsulates PyCurl operations"""

    def __init__(self, **opts):
        """Initializes a pycurl handle"""
        self.c = pycurl.Curl()
        curlopts = [('cert', pycurl.SSLCERT), ('key', pycurl.SSLKEY), ('verbose', pycurl.VERBOSE)]
        if hasattr(pycurl, 'KEYPASSWD'):
            curlopts += [('pass', pycurl.KEYPASSWD)]    # Option added to PyCurl 7.21.5
        else:
            curlopts += [('pass', pycurl.SSLCERTPASSWD)]
        for opt, curlopt in curlopts:
            if opts[opt] is not None:
                self.c.setopt(curlopt, opts[opt])
        self.c.setopt(pycurl.SSL_VERIFYPEER, 0)
        if opts['verbose'] is not None:
            if opts['verbose'] > 1:
                self.c.setopt(pycurl.DEBUGFUNCTION, self._debug_function)
        self.c.setopt(pycurl.HEADERFUNCTION, self._header_function)
        self.c.setopt(pycurl.USERAGENT, '%s/%s %s' % (progname, version, pycurl.version))
        self.buf = BytesIO()
        try:
            self.c.setopt(pycurl.WRITE, self.buf)
        except AttributeError:
            self.c.setopt(pycurl.WRITEFUNCTION, self.buf.write)

    def __del__(self):
        """Closes the pycurl handle"""
        self.buf.close()
        self.c.close()

    def _debug_function(self, t, m):
        """Debug function used to mimic curl's debug output"""
        curl_prefix = {pycurl.INFOTYPE_TEXT: '* ',
                       pycurl.INFOTYPE_HEADER_IN: '< ', pycurl.INFOTYPE_HEADER_OUT: '> ',
                       pycurl.INFOTYPE_DATA_IN: '', pycurl.INFOTYPE_DATA_OUT: ''}
        # Ignore SSL info types
        if curl_prefix.get(t) is None:
            return
        m = m.decode('iso-8859-1').rstrip()
        if t == pycurl.INFOTYPE_HEADER_OUT:
            m = m.replace(r'\n', r'\n' + curl_prefix[t])
        print(curl_prefix[t] + m)

    # Adapted from https://github.com/pycurl/pycurl/blob/master/examples/quickstart/response_headers.py
    def _header_function(self, header_line):
        """Gets the HTTP headers from a response"""
        # HTTP standard specifies that headers are encoded in iso-8859-1
        header_line = header_line.decode('iso-8859-1')
        # Header lines include the first status line (HTTP/1.x ...)
        if ':' not in header_line:
            if self.headers.get('HTTP_STATUS') is None:
                self.headers['HTTP_STATUS'] = header_line.strip()
            return
        # Break the header line into header name and value.
        name, value = header_line.split(':', 1)
        # Remove whitespace that may be present.
        name = name.strip().lower()
        value = value.strip()
        self.headers[name] = value

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

    _cached_info = {'': {}}

    def __init__(self, registry):
        """Gets the boto3 handle"""
        try:
            import boto3
        except ImportError:
            print("ERROR: Install the boto3 Python library to get data from AWS ECR", file=sys.stderr)
            sys.exit(1)
        try:
            self._c = boto3.client('ecr')
        except NoCredentialsError:
            print("ERROR: Unable to locate credentials", file=sys.stderr)
            sys.exit(1)
        m = re.search("^(?:https?://)?([0-9]{12})\.*", registry)
        self._registryId = m.group(1)

    def get_repositories(self):
        """Returns a list of repositories"""
        repositories = []
        paginator = self._c.get_paginator('describe_repositories')
        for response in paginator.paginate(registryId=self._registryId):
            repositories += [item['repositoryName'] for item in response['repositories']]
        return repositories

    def get_tags(self, repo):
        """Returns a list of tags for the specified repository"""
        tags = []
        self._cached_info = {repo: {}}
        keys = (('Digest', 'imageDigest'), ('CompressedSize', 'imageSizeInBytes'))
        image_filter = {'tagStatus': 'TAGGED'}
        paginator = self._c.get_paginator('describe_images')
        for response in paginator.paginate(registryId=self._registryId, repositoryName=repo, filter=image_filter):
            for item in response['imageDetails']:
                tags += item['imageTags']
                for tag in item['imageTags']:
                    self._cached_info[repo][tag] = {k1: item[k2] for (k1, k2) in keys}
        return tags

    def get_image_info(self, repo, tag):
        """Returns a dictionary with image info such as Digest and CompressedSize"""
        try:
            return self._cached_info[repo][tag]
        except KeyError:
            pass
        info = {}
        data = self._c.describe_images(registryId=self._registryId, repositoryName=repo, imageIds=[{'imageTag': tag}])
        data = data['imageDetails'][0]
        info['Digest'] = data['imageDigest']
        info['CompressedSize'] = data['imageSizeInBytes']
        return info

    def get_manifest(self, repo, tag):
        """Returns the image manifest as a dictionary"""
        data = self._c.batch_get_image(registryId=self._registryId, repositoryName=repo, imageIds=[{'imageTag': tag}])
        return json.loads(data['images'][0]['imageManifest'])


class DockerRegistryError(Exception):
    """This class is used to raise Docker Registry errors"""
    pass


class DockerRegistryV2:
    """This class encapsulates operations to get information from a Docker Registry v2"""

    _cached_manifest = {}
    _basic_auth = ""
    _headers = []
    _aws_ecr = None

    def __init__(self, registry, **args):
        """Get a Curl handle and checks the type and availability of the Registry"""
        self._c = Curl(**args)
        self._registry = registry
        # Assume https:// by default
        if not re.match("https?://", self._registry):
            self._registry = "https://" + self._registry
        # Check for AWS EC2 Container Registry
        if re.match("(?:https?://)?[0-9]{12}\.dkr\.ecr\.[a-z0-9]+[a-z0-9-]*\.amazonaws\.com(?::\d+)?$", self._registry):
            self._aws_ecr = DockerRegistryECR(self._registry)
            return
        # Set credentials if specified or set in ~/.docker/config.json
        if args['user'] is not None:
            if ':' not in args['user']:
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
        del(fields['Bearer realm'])
        fields = urlencode(fields)
        if use_post:
            token = json.loads(self._c.post(url, fields, auth=self._auth_basic()))['token']
        else:
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
            if http_code == 429:    # Too many requests
                sleep(0.1)
                continue
            elif http_code == 401 and tries > 0:
                headers = headers[:]
                auth_method = self._c.get_headers('www-authenticate')
                if auth_method is None or auth_method.startswith('Basic '):
                    headers += self._auth_basic()
                elif auth_method.startswith('Bearer '):
                    headers += self._auth_token(auth_method)
                else:
                    print('ERROR: Unsupported authentication method: ' + auth_method, file=sys.stderr)
                    sys.exit(1)
            else:
                if not self._headers and self._basic_auth and tries == 1:
                    self._headers = self._auth_basic()
                try:
                    data = json.loads(body)
                except ValueError:
                    return body
                if data.get('errors') is not None:
                    raise DockerRegistryError(data['errors'][0]['message'])
                else:
                    return data
            tries -= 1

    def _check_registry(self):
        """Checks for a valid Docker Registry"""
        body = self._get("")
        if body == {} or body == "":
            return
        http_code = self._c.get_http_code()
        if http_code == 404:
            error = 'Invalid v2 Docker Registry: ' + self._registry
        else:
            error = self._c.get_headers('HTTP_STATUS')
            if error is not None and not error:
                error = "Invalid HTTP server"
        print('ERROR: ' + error, file=sys.stderr)
        sys.exit(1)

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
            return
        auth = ""
        f = open(os.path.expanduser("~/.docker/config.json"), "r")
        config = json.load(f)
        try_registry = [re.sub("^https?://", "", self._registry)]
        if not re.search(':\d+$', try_registry[0]):
            if self._registry.startswith('https://'):
                try_registry += [try_registry[0] + ':443']
            elif self._registry.startswith('http://'):
                try_registry += [try_registry[0] + ':80']
        else:
            if self._registry.startswith('https://'):
                try_registry += [try_registry[0][:-len(':443')]]
            elif self._registry.startswith('http://'):
                try_registry += [try_registry[0][:-len(':80')]]
        for registry in try_registry:
            try:
                auth = config['auths'][registry]['auth']
                if auth:
                    break
            except KeyError:
                pass
        f.close()
        return auth

    def _get_paginated(self, s):
        """Get paginated results when the Registry is too large"""
        elements = []
        while True:
            url = self._c.get_headers('link')
            if url is None:
                break
            m = re.match('</v2/(.*)>; rel="next"', url)
            url = m.group(1)
            data = self._get(url)
            elements += data[s]
        return elements

    def get_repositories(self):
        """Returns a list of repositories"""
        if self._aws_ecr is not None:
            repositories = self._aws_ecr.get_repositories()
        else:
            data = self._get("_catalog")
            repositories = data['repositories'] + self._get_paginated('repositories')
        repositories.sort()
        return repositories

    def get_tags(self, repo):
        """Returns a list of tags for the specified repository"""
        if self._aws_ecr is not None:
            tags = self._aws_ecr.get_tags(repo)
        else:
            data = self._get(repo + "/tags/list")
            tags = data['tags'] + self._get_paginated('tags')
        tags.sort()
        return tags

    def get_manifest(self, repo, tag, version):
        """Returns the image manifest as a dictionary. The schema versions must be 1 or 2"""
        assert version in (1, 2)
        image = repo + ":" + tag
        try:
            manifest = self._cached_manifest[image][version]
            if manifest:
                return manifest
        except KeyError:
            self._cached_manifest = {image: ['', '', '']}
        if self._aws_ecr is not None:
            assert version == 1
            self._cached_manifest[image][version] = self._aws_ecr.get_manifest(repo, tag)
        else:
            headers = ["Accept: application/vnd.docker.distribution.manifest.v%d+json" % (version)]
            self._cached_manifest[image][version] = self._get(repo + "/manifests/" + tag, headers=headers)
        return self._cached_manifest[image][version]

    def get_image_info(self, repo, tag):
        """Returns a dictionary with image info containing the most interesting items"""
        info = {}
        manifest = self.get_manifest(repo, tag, 1)
        data = json.loads(manifest['history'][0]['v1Compatibility'])
        info.update({key.title(): data[key] for key in ('architecture', 'created', 'docker_version', 'os')})
        keys = ('Cmd', 'Entrypoint', 'Env', 'ExposedPorts', 'Healthcheck', 'Labels', 'OnBuild', 'User', 'Volumes', 'WorkingDir')
        info.update({key: data['config'][key] for key in keys if data['config'].get(key) is not None})
        # Before Docker 1.9.0, ID's were not digests but random bytes
        info['Digest'] = "-"
        if self._aws_ecr is not None:
            info.update(self._aws_ecr.get_image_info(repo, tag))
        elif info['Docker_Version'] and int(info['Docker_Version'].replace('.', '')) >= 190:
            manifest = self.get_manifest(repo, tag, 2)
            try:
                info['Digest'] = manifest['config']['digest']
            except KeyError:
                pass
            # Calculate compressed size
            info['CompressedSize'] = sum((item['size'] for item in manifest['layers']))
        info['Digest'] = info['Digest'].replace('sha256:', '')
        return info

    def get_image_history(self, repo, tag):
        """Returns a list containing the image history (layers)"""
        history = []
        manifest = self.get_manifest(repo, tag, 1)
        prefix = '/bin/sh -c #(nop)'
        for item in reversed(manifest['history']):
            data = json.loads(item['v1Compatibility'])['container_config']['Cmd']
            history += [" ".join(data).replace(prefix, "").replace("/bin/sh -c", "RUN").lstrip()]
        return history


# Converts a size in bytes to a string in KB, MB, GB or TB
def pretty_size(size):
    if not size:
        return ""
    if size < 1024:
        return str(size)
    units = ('', 'K', 'M', 'G', 'T')
    for n in (4, 3, 2, 1):
        if (size > 1024**n):
            return "%.2f %cB" % ((float(size) / 1024**n), units[n])


# Converts date/time string in ISO-8601 format to date(1)
def pretty_date(ts):
    fmt = "%a %b %d %H:%M:%S %Z %Y"
    return strftime(fmt, localtime(timegm(strptime(re.sub("\.\d+Z$", "GMT", ts), '%Y-%m-%dT%H:%M:%S%Z'))))


def main():
    parser = argparse.ArgumentParser(usage=usage, add_help=False)
    parser.add_argument('-c', '--cert')
    parser.add_argument('-k', '--key')
    parser.add_argument('-p', '--pass')
    parser.add_argument('-u', '--user')
    parser.add_argument('-r', '--reverse', action='store_false')
    parser.add_argument('-s', '--size', action='store_true')
    parser.add_argument('-t', '--time', action='store_true')
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
    except AttributeError:
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
        except DockerRegistryError as error:
            registry_error(error)

        # Print image info

        info['CompressedSize'] = pretty_size(info.get('CompressedSize'))
        info['Created'] = pretty_date(info['Created'])

        # Convert 'PATH=xxx foo=bar' into 'PATH="xxx" foo="bar"'
        info["Env"] = [re.sub('([^=]+)=(.*)', r'\1="\2"', env.replace('"', r'\"')) for env in info["Env"]]

        keys = list(info)
        keys.sort()
        for key in keys:
            value = info[key]
            if type(value) is dict:
                if key == "Labels" or key == "Healthcheck":
                    value = str(json.dumps(value))
                else:
                    value = list(value)
            if type(value) is list:
                if key in ('Env', 'ExposedPorts'):
                    value = " ".join(sorted(value))
                else:
                    value = "[ '" + "".join("', '".join(item for item in value)) + "' ]"
            if not PY3:
                value = value.encode('utf-8')
            print('%-15s\t%s' % (key.replace('_', ''), value))

        # Print image history
        try:
            history = reg.get_image_history(repo, tag)
        except DockerRegistryError as error:
            registry_error(error)
        for i, layer in enumerate(history, 1):
            if not PY3:
                layer = layer.encode('utf-8')
            print('%-15s\t%s' % ('History[' + str(i) + ']', layer))
        sys.exit(0)

    # Print information on all images

    try:     # Python 3
        columns = shutil.get_terminal_size(fallback=(158, 40)).columns
    except:  # Unix only
        columns = int(subprocess.check_output(['/bin/stty', 'size']).split()[1])
    cols = int(columns / 3)

    print("%-*s\t%-12s\t%-30s\t%s\t%s" % (cols, "Image", "Id", "Created on", "Docker", "Compressed Size"))

    cache = {}

    for repo in reg.get_repositories():
        try:
            tags = reg.get_tags(repo)
        except DockerRegistryError as error:
            print("%-*s\tERROR: %s" % (cols, repo, error))
            continue
        for tag in tags:
            try:
                info = reg.get_image_info(repo, tag)
            except DockerRegistryError as error:
                print("%-*s\tERROR: %s" % (cols, repo + ":" + tag, error))
                continue
            if args.size or args.time:
                cache[repo + ":" + tag] = info
            else:
                info['Created'] = pretty_date(info['Created'])
                info['CompressedSize'] = pretty_size(info.get('CompressedSize'))
                print("%-*s\t%-12s\t%s\t%s\t%s" % (cols, repo + ":" + tag,
                      info['Digest'][0:12], info['Created'], info['Docker_Version'], info['CompressedSize']))

    # Show output sorted by size or time
    images = []
    if args.size:
        images = sorted(cache, key=lambda k: cache[k].get('CompressedSize', 0), reverse=args.reverse)
    elif args.time:
        images = sorted(cache, key=lambda k: cache[k]['Created'], reverse=args.reverse)

    for image in images:
        cache[image]['Created'] = pretty_date(cache[image]['Created'])
        cache[image]['CompressedSize'] = pretty_size(cache[image].get('CompressedSize'))
        print("%-*s\t%-12s\t%s\t%s\t%s" % (cols, image,
              cache[image]['Digest'][0:12], cache[image]['Created'], cache[image]['Docker_Version'], cache[image]['CompressedSize']))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

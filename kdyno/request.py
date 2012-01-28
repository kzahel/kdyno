from util import signer
import time
from tornado.escape import utf8
from tornado.util import b
from tornado.escape import native_str
import re
from tornado.httputil import HTTPHeaders
from tornado.options import options
import xml.parsers.expat
import logging
import json


import urllib
def escape(s):
    return urllib.quote(s, safe='-_~')

def urlencode(d):
    # not the same as urllib's urlencode (which makes signatures not match)
    if isinstance(d, dict):
        d = d.iteritems()
    return '&'.join(['%s=%s' % (escape(k), escape(v)) for k, v in d])

def parse_headers(data):
    data = native_str(data.decode("latin1"))
    first_line, _, header_data = data.partition("\n")
    match = re.match("HTTP/1.[01] ([0-9]+)", first_line)
    assert match
    code = int(match.group(1))
    headers = HTTPHeaders.parse(header_data)
    return code, headers

def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)

def parse_headers(data):
    data = native_str(data.decode("latin1"))
    first_line, _, header_data = data.partition("\n")
    match = re.match("HTTP/1.[01] ([0-9]+)", first_line)
    assert match
    code = int(match.group(1))
    headers = HTTPHeaders.parse(header_data)
    return code, headers

class AWSRequest(object):
    def __init__(self, method, host, parameters=None):
        self.method = method
        self.host = host
        self.path = '/'
        self.parameters = parameters or {}
        self.headers  = { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8', 
                          'Host': host }

    def to_postdata(self):
        return urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in self.parameters.iteritems()])

    def to_json_postdata(self):
        self.headers['Content-Type'] = 'application/x-amz-json-1.0'
        return json.dumps(self.parameters)

    def get_normalized_parameters(self):
        """
        Returns a list constisting of all the parameters required in the
        signature in the proper order.

        """
        return urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in 
                            sorted(self.parameters.iteritems()) 
                            if k != 'Signature'])

    def get_normalized_http_method(self):
        return self.method.upper()

    def get_normalized_http_path(self):
        return self.path

    def get_normalized_http_host(self):
        return self.host.lower()

    def set_parameter(self, name, value):
        self.parameters[name] = value

    def generate_timestamp(self):
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())

    def sign_request(self, aws_key, aws_secret):
        self.set_parameter('AWSAccessKeyId', aws_key)
        self.set_parameter('SignatureVersion', signer.version)
        self.set_parameter('SignatureMethod', signer.name)
        self.set_parameter('Timestamp', self.generate_timestamp())
        self.set_parameter('Signature', signer.build_signature(self, aws_secret))

    def make_request_headers(self):
        req_path = '/'
        request_lines = [utf8("%s %s HTTP/1.1" % (self.method,
                                                  req_path))]
        for k, v in self.headers.items():
            line = utf8(k) + b(": ") + utf8(v)
            request_lines.append(line)
        toreturn = b("\r\n").join(request_lines) + b("\r\n\r\n")
        return toreturn
        #if self.request.body is not None:
        #    self.stream.write(self.request.body)



class ResponseParser(object):
    def __init__(self, data):
        self.results = []
        self.attributes = {}
        self.meta = {}
        p = xml.parsers.expat.ParserCreate()
        p.StartElementHandler = self.start_elt
        p.EndElementHandler = self.end_elt
        p.CharacterDataHandler = self.data
        self.stack = []
        self._new_select_result = None
        self._cur_encoding = None
        p.Parse(data)
        if 'NextToken' in self.meta:
            self.meta['NextToken'] = ''.join( self.meta['NextToken'] )

    def start_elt(self, name, attrs):
        if 'encoding' in attrs:
            self._cur_encoding = attrs['encoding']
        self.stack.append(name)

        if self.stack == ['SelectResponse','SelectResult']:
            self._new_select_result = True
        #logging.info('start elt %s %s' % (name, attrs))

    def end_elt(self, name):
        if self._cur_encoding:
            self._cur_encoding = None
        #logging.info('end elt %s' % name)
        if self.stack == ['SelectResponse','SelectResult','Item']:
            self.results.append( { self._new_select_result: self.attributes } )
            self.attributes = {}
            self._new_select_result = None

        self.stack.pop()

    def data(self, data):
        if self.stack == ['SelectResponse','SelectResult','Item','Name']:
            self._new_select_result = data
        elif self.stack[:3] == ['GetSessionTokenResponse', 'GetSessionTokenResult', 'Credentials']:
            if len(self.stack) > 3:
                self.meta[self.stack[-1]] = data
        elif self.stack[-1] == 'NextToken':
            if 'NextToken' not in self.meta:
                self.meta['NextToken'] = []
            self.meta['NextToken'].append( data.strip() )
        elif len(self.stack) > 2 and self.stack[-2] == 'Attribute':
            #logging.info('got attribute in %s' % self.stack)
            if self._cur_encoding:
                data = base64.b64decode( data )
            if self.stack[-1] == 'Name':
                self._cur_name = data
            else:
                if self._cur_name in self.attributes:
                    if len(self.stack) > 1 and self.stack[1] == 'GetAttributesResult':
                        # &amp; causes data to be called multiple
                        # times even for inside a single thing
                        self.attributes[self._cur_name] += data
                    else:
                        if hasattr( self.attributes[self._cur_name], '__iter__' ):
                            self.attributes[self._cur_name].append( data )
                        else:
                            self.attributes[self._cur_name] = [ self.attributes[self._cur_name], data ]
                else:
                    self.attributes[self._cur_name] = data
        elif len(self.stack) > 2 and self.stack[-2] == 'DomainMetadataResult':
            self.attributes[self.stack[-1]] = data
        elif self.stack[-1] == 'DomainName':
            if 'DomainName' not in self.attributes:
                self.attributes['DomainName'] = []
            self.attributes['DomainName'].append( data )
        elif self.stack[-1] in ['BoxUsage', 'RequestId']:
            self.meta[self.stack[-1]] = data
        else:
            #logging.info('parser unhandled %s data %s' % (self.stack, data))
            pass

class Response(object):
    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self.error = self.code != 200
        if 'debug' in options and options.debug:
            self.body = body
        self.attributes = None
        self.parsexml(body)

    def parsexml(self, body):
        parser = ResponseParser(body)
        self.attributes = parser.attributes
        self.meta = parser.meta
        self.results = parser.results

    def get(self, key, default=None):
        if self.attributes:
            if key in self.attributes:
                return self.attributes[key]
        if default: return default

class JSONResponse(object):
    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self.error = self.code != 200
        if 'debug' in options and options.debug:
            self.body = body
        self.attributes = json.loads(body)

import socket

import tornado.iostream
import logging
import functools
from tornado import gen

from request import AWSRequest, parse_headers
from request import Response, JSONResponse
from util import HmacAuthV3HTTPHandler
import pdb

class Request(object):
    ServiceName = 'DynamoDB'
    """The name of the Service"""
    
    Version = '20111205'
    """DynamoDB API version."""

    def __init__(self, action, body):
        headers = {'X-Amz-Target' : '%s_%s.%s' % (self.ServiceName,
                                                  self.Version, action),
                   'Content-Type' : 'application/x-amz-json-1.0',
                   'Content-Length' : str(len(body))}
        

class STS(object):
    DefaultRegionName = 'us-east-1'
    DefaultRegionEndpoint = 'sts.amazonaws.com'
    APIVersion = '2011-06-15'

    @gen.engine
    def get_session_token(self, callback=None):
        logging.info('retreiving session token')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.SSLIOStream(s)
        stream._always_callback = True # get callbacks on stream.connect
        yield gen.Task( stream.connect, (self.DefaultRegionEndpoint,443) )
        if stream.error:
            callback(False)
            raise StopIteration

        request = AWSRequest('POST', self.DefaultRegionEndpoint, {'Action':'GetSessionToken'})
        request.set_parameter('Version', self.APIVersion)
        request.sign_request(self.aws_key, self.aws_secret)
        body = request.to_postdata()
        request.headers['Content-Length'] = str(len(body))
        towrite = request.make_request_headers() + body
        #logging.info('writing %s' % towrite)
        yield gen.Task( stream.write, towrite )
        rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
        code, headers = parse_headers(rawheaders)
        if code != 200:
            logging.error('got error response %s, %s' % (code, headers))
        if 'Content-Length' in headers:
            body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
            #logging.info('got body %s' % body)
            response = Response( code, headers, body )
            callback( response )
        else:
            logging.error('chunked encoding response?')
            pdb.set_trace()


class KDyno(STS, HmacAuthV3HTTPHandler):

    DefaultHost = 'dynamodb.us-east-1.amazonaws.com'

    def __init__(self, aws_key, aws_secret, db=None, secure=True, name=None):
        self.db = db or self.DefaultHost
        self.secure = secure
        self.aws_key = aws_key
        self.aws_secret = aws_secret
        self.streams = {}
        self.name = name
        self.session_token = None
        HmacAuthV3HTTPHandler.__init__(self, self.db, None, self.aws_secret)

    @gen.engine
    def get_stream(self, callback):
        found = False
        for stream,v in self.streams.iteritems():
            if not stream._connecting and not stream._current_request and not stream.closed():
                found = True
                logging.info('%sfound usable db connection (%s total)' % (self.name+' ' if self.name else '', len(self.streams)))
                callback(stream)
                break
        if not found:
            logging.info('%screating new db connection' % (self.name+' ' if self.name else ''))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            if self.secure:
                stream = tornado.iostream.SSLIOStream(s)
                addr = (self.db, 443)
            else:
                stream = tornado.iostream.IOStream(s)
                addr = (self.db, 80)
            stream._current_request = None
            stream.set_close_callback(functools.partial(self.on_close, stream))
            #logging.info('connecting to %s' % self.db)
            yield gen.Task( stream.connect, addr )
            #logging.info('connected')
            stream._debug_info = 'ksdb stream'
            self.streams[ stream ] = None
            callback(stream)

    def remove_connection(self, stream):
        if not stream.closed(): stream.close()
        if stream in self.streams:
            del self.streams[stream]

    def on_close(self, stream):
        logging.warn('db connection close')
        if stream._current_request:
            # likely "read error" on socket iostream.py
            if stream._current_request:
                logging.error('db connection closed while had _current_request')
        self.remove_connection(stream)

    @gen.engine
    def do_request(self, target, params, callback=None):
        if not self.session_token:
            response = yield gen.Task( self.get_session_token )
            if not response or response.error:
                callback(Exception('failed to retreive token'))
                raise StopIteration
            self.session_token = response.meta
            self.update_secret( str(response.meta['SecretAccessKey']) )

        logging.info('got session token')
        stream = yield gen.Task( self.get_stream )
        request = AWSRequest('POST', self.DefaultHost, params)
        body = request.to_json_postdata()
        request.body = body
        request.headers['X-Amz-Target'] = 'DynamoDB_20111205.%s' % target
        self.add_auth(request, security_token = self.session_token['SessionToken'], access_key = self.session_token['AccessKeyId'])
        request.headers['Content-Length'] = str(len(body))
        towrite = request.make_request_headers() + body
        yield gen.Task( stream.write, towrite )
        rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
        code, headers = parse_headers(rawheaders)
        if code != 200:
            logging.error('got error response %s, %s' % (code, headers))
            # detect for invalid expired session token and expire it...
            self.session_token = None
        if 'Content-Length' in headers:
            body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
            response = JSONResponse( code, headers, body )
            logging.info('got response :%s, %s' % (response, response.attributes))
            callback( response )
        else:
            logging.error('chunked encoding response?')
            pdb.set_trace()

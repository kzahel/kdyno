import socket

import tornado.iostream
import logging
import functools
from tornado import gen

from request import AWSRequest, parse_headers
from request import Response, JSONResponse
from util import HmacAuthV3HTTPHandler
import pdb
import tornado.ioloop
import time
from tornado.options import options

def asyncsleep(t, callback=None):
    logging.info('sleeping %s' % t)
    tornado.ioloop.IOLoop.instance().add_timeout( time.time() + t, callback )

class ErrorResponse(object):
    def __init__(self, message):
        self.code = 599
        self.error = True
        self.headers = None
        self.message = message
        self.attributes = None

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
    def get_session_token(self, duration_seconds=None, callback=None):
        logging.info('retreiving session token')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.SSLIOStream(s)
        stream._always_callback = True # get callbacks on stream.connect
        addr = (self.DefaultRegionEndpoint,443)
        yield gen.Task( stream.connect, addr )
        if stream.error:
            callback(ErrorResponse('error connecting to %s to get token' % str(addr) ) )
            raise StopIteration

        data = {'Action':'GetSessionToken'}
        if duration_seconds:
            data['DurationSeconds'] = duration_seconds
        request = AWSRequest('POST', self.DefaultRegionEndpoint, data)
        request.set_parameter('Version', self.APIVersion)
        request.sign_request(self.aws_key, self.aws_secret)
        body = request.to_postdata()
        request.headers['Content-Length'] = str(len(body))
        towrite = request.make_request_headers() + body
        #logging.info('writing %s' % towrite)
        yield gen.Task( stream.write, towrite )
        rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
        if not rawheaders:
            logging.error('read until headers returned null, likely socket closed...')
            callback( ErrorResponse('socket closed') )
            raise StopIteration

        code, headers = parse_headers(rawheaders)
        if code != 200:
            logging.error('get token: got error response %s, %s' % (code, headers))
            callback( ErrorResponse('non 200 response %s' % code ) )
            stream.close()
            raise StopIteration
        if 'Content-Length' in headers:
            body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
            if not body:
                logging.error('conn closed reading for body?')
                callback( ErrorResponse('socket closed') )
                raise StopIteration
            #logging.info('got body %s' % body)
            response = Response( code, headers, body )
            callback( response )
        else:
            logging.error('chunked encoding response?')
            callback( ErrorResponse('unable to parse chunked encoding') )
        if not stream.closed(): stream.close()

class DynamoTable(object):
    def __init__(self, db, name):
        ''' convenience thing '''
        self.db = db
        self.name = name

    def get(self, key, callback=None):
        self.db.get_item( self.name, key, callback=callback )

    def put(self, key, attrs, callback=None):
        dattrs = {}
        for k,v in attrs.items():
            dattrs[k] = {'S':str(v)}

        self.db.put_item( self.name, dattrs, callback=callback)

    def delete(self, key, key_type=None, callback=None):
        key_type = key_type or 'S'
        dkey = { 'HashKeyElement': { key_type: key } }
        self.db.delete_item( self.name, dkey, callback=callback )

    @gen.engine
    def get_by_attribute(self, k, v, callback=None):
        if k == 'cid':
            if options.users_database == 'users':
                table_name = 'users_cid'
            else:
                table_name = 'users_cid_dev'
        result = yield gen.Task( self.db.get_item, table_name, v )
        if result.code == 200 and 'Item' in result.attributes:
            username = result.attributes['Item']['username'].values()[0]
            callback( [ {'username':username} ] )
        else:
            callback( None )


class KDyno(STS, HmacAuthV3HTTPHandler):

    DefaultHost = 'dynamodb.us-east-1.amazonaws.com'

    def __init__(self, aws_key, aws_secret, db=None, secure=False, name=None):
        self.db = db or self.DefaultHost
        self.secure = secure
        self.aws_key = aws_key
        self.aws_secret = aws_secret
        self.streams = {}
        self.name = name
        self.session_token = None
        HmacAuthV3HTTPHandler.__init__(self, self.db, None, self.aws_secret)

    def get_domain(self, name):
        return DynamoTable(self, name)

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
            stream._always_callback = True
            stream.set_close_callback(functools.partial(self.on_close, stream))
            #logging.info('connecting to %s' % self.db)
            yield gen.Task( stream.connect, addr )
            if stream.error:
                logging.error('error in connecting...')
                callback(ErrorResponse('error connecting to %s' % str(addr)))
            else:
                #logging.info('connected')
                stream._debug_info = 'kdyno stream'
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
                if hasattr(stream._current_request,'callback') and stream._current_request.callback:
                    stream._current_request.callback( ErrorResponse('connection closed') )
        self.remove_connection(stream)

    @gen.engine
    def create_table(self, name, hash_key, hash_key_type=None, range_key=None, range_key_type=None, read_units=3, write_units=5, callback=None):
        hash_key_type = 'S' or hash_key_type

        data = { 'TableName': name,
                 'KeySchema': { 'HashKeyElement': { 'AttributeName': hash_key, 'AttributeType': hash_key_type } },
                 'ProvisionedThroughput': { 'ReadCapacityUnits': read_units, 'WriteCapacityUnits': write_units } }

        range_key_type = 'S' or range_key_type
        if range_key:
            data['KeySchema']['RangeKeyElement'] = { 'AttributeName': range_key, 'AttributeType': range_key_type }

        resp = yield gen.Task( self.do_request, 'CreateTable', data )
        callback(resp)

    @gen.engine
    def describe_table(self, name, callback):
        resp = yield gen.Task( self.do_request, 'DescribeTable', {'TableName': name} )
        callback(resp)

    @gen.engine
    def delete_table(self, name, callback):
        resp = yield gen.Task( self.do_request, 'DeleteTable', {'TableName': name} )
        callback(resp)

    @gen.engine
    def list_tables(self, start_name=None, limit=None, callback=None):
        data = {}
        if limit:
            data['Limit'] = limit
        if start_name:
            data['ExclusiveTableStartName'] = start_name
        resp = yield gen.Task( self.do_request, 'ListTables', data )
        callback(resp)

    @gen.engine
    def get_item(self, table_name, hash_key, hash_key_type=None, range_key=None, range_key_type=None, attrs=None, consistent=False, callback=None):
        hash_key_type = 'S' or hash_key_type
        data = { 'TableName': table_name,
                 'Key': { 'HashKeyElement': { hash_key_type: hash_key } }
                 }
        if range_key:
            range_key_type = 'S' or range_key_type
            data['Key']['RangeKeyElement'] = { range_key_type: range_key }
        if consistent:
            data['ConsistentRead'] = consistent
        if attrs:
            data['AttributesToGet'] = attrs
        resp = yield gen.Task( self.do_request, 'GetItem', data )
        callback(resp)

    @gen.engine
    def put_item(self, table_name, item, expected=None, callback=None):
        data = { 'TableName': table_name,
                 'Item': item }
        if expected:
            data['Expected'] = expected
        resp = yield gen.Task( self.do_request, 'PutItem', data )
        callback(resp)

    @gen.engine
    def delete_item(self, table_name, key, expected=None, callback=None):
        data = { 'TableName': table_name,
                 'Key': key }
        if expected:
            data['Expected'] = expected
        resp = yield gen.Task( self.do_request, 'DeleteItem', data )
        callback(resp)

    @gen.engine
    def do_request(self, target, params, retry_if_invalid_stream=True, retry_on_expired_token=True, callback=None):
        if options.verbose > 0:
            logging.info('request %s %s' % (target, params))
        if not self.session_token:
            response = yield gen.Task( self.get_session_token, duration_seconds=3600 )
            if response.error:
                callback(response)
                raise StopIteration
            self.session_token = response.meta
            self.update_secret( str(response.meta['SecretAccessKey']) )
            logging.info('got session token')

        stream_tries = 0
        while stream_tries <= 2:
            stream_tries += 1
            stream = yield gen.Task( self.get_stream )
            if stream.error:
                logging.error('error getting stream %s' % stream)
                callback( ErrorResponse('unable to get stream') )
                raise StopIteration
            request = AWSRequest('POST', self.DefaultHost, params)
            body = request.to_json_postdata()
            request.body = body
            request.headers['X-Amz-Target'] = 'DynamoDB_20111205.%s' % target

            if not self.session_token:
                err = 'session token was invalidated while getting a db connection'
                logging.error(err)
                callback( ErrorResponse(err) )
                raise StopIteration

            self.add_auth(request, security_token = self.session_token['SessionToken'], access_key = self.session_token['AccessKeyId'])
            request.headers['Content-Length'] = str(len(body))
            towrite = request.make_request_headers() + body
            stream._current_request = request
            #request.callback = callback # we're handling error states ourselves

            #logging.info('writing to stream..')
            yield gen.Task( stream.write, towrite )
            if stream.error:
                logging.error('connection died while writing to it')
                callback( ErrorResponse('connection died while writing') )
                raise StopIteration
            #yield gen.Task( asyncsleep, 10 )# for testing
            #logging.info('reading from stream')
            rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )
            if not rawheaders or stream.error:
                logging.error('connection seems to have closed..')
                # if error is read error connection reset by peer, the request probably never made it in... (dead stream)...
                # if so, perhaps re-try.
                #callback( ErrorResponse('connection closed on reading for headers') )
                #raise StopIteration
            else:
                break

        code, headers = parse_headers(rawheaders)
        if 'Content-Length' in headers:
            body = yield gen.Task( stream.read_bytes, int(headers['Content-Length']) )
            if code != 200:
                logging.error('got error response %s, %s, %s' % (code, headers, body))
            #logging.info('GOT BODY %s' % body)
            if not body:
                callback( ErrorResponse('connection closed on reading for body') )
                raise StopIteration
            request.callback = None
            stream._current_request = None
            response = JSONResponse( code, headers, body )
            if options.verbose > 1 and code == 200:
                logging.info('got response :%s, %s' % (response, response.attributes))

            if code == 400 and response.attributes and '__type' in response.attributes and response.attributes['__type'].endswith('ExpiredTokenException'):
                self.session_token = None
                # re-do this request...
                if retry_on_expired_token:
                    result = yield gen.Task( self.do_request, target, params, retry_if_invalid_stream=True, retry_on_expired_token=False )
                    callback(result)
                    raise StopIteration

            callback( response )
        else:
            logging.error('chunked encoding response?')
            callback( ErrorResponse('no content length header') )

        if len(self.streams) > 25:
            logging.warn('too many db connections %s -- closing one' % len(self.streams))
            self.remove_connection(stream)

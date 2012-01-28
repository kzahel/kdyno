import logging
from tornado import gen
import tornado.ioloop
ioloop = tornado.ioloop.IOLoop.instance()
from kdyno.config import config
from kdyno.kdyno import KDyno
db = KDyno(config['sdb_access_key'], config['sdb_access_secret'], secure=False)
import pdb

import tornado.options
tornado.options.parse_command_line()

@gen.engine
def basic():
    #params = {"Item": {"name": {"S": "foobar"}}, "TableName": "users_dev"}
    
    params = {"TableName": "users_dev"}
    yield gen.Task( db.do_request, 'DescribeTable', params )

    params = {"Item": {"name": {"S": "foobar"}}, "TableName": "users_dev"}
    yield gen.Task( db.do_request, 'PutItem', params )



ioloop.add_callback( basic )
ioloop.start()

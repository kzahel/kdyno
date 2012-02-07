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
def overload(n=10):
    usernames = ['testuser%s' % i for i in range(n)]
    while True:

        tasks = [ gen.Task( db.do_request, 
                            'PutItem',
                            {"Item": {"username": {"S": username}}, "TableName": "users_dev"} ) for username in usernames]
        


        resp = yield gen.Multi( tasks )
        logging.info('puts resp %s ' % [r.code for r in resp])

        tasks = [ gen.Task( db.get_item,
                            'users_dev',
                            username ) for username in usernames ]

        resp = yield gen.Multi( tasks )
        logging.info('gets resp %s ' % [r.code for r in resp])



ioloop.add_callback( overload )



ioloop.start()

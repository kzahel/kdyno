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
    resp = yield gen.Task( db.do_request, 'DescribeTable', params )
    logging.info('resp %s' % resp.attributes)

    params = {"Item": {"name": {"S": "foobar"}}, "TableName": "users_dev"}
    yield gen.Task( db.do_request, 'PutItem', params )


@gen.engine
def test_tables():
    #resp = yield gen.Task( db.list_tables )
    table_name = 'FooTable'

    resp = yield gen.Task( db.describe_table, table_name )
    if resp.error and resp.attributes['__type'].endswith('ResourceNotFoundException'):
        pass
    else:
        # delete the table
        resp = yield gen.Task( db.delete_table, table_name )
        assert resp.code == 200
        while True:
            resp = yield gen.Task( db.describe_table, table_name )
            if resp.error and resp.attributes['__type'].endswith('ResourceNotFoundException'):
                logging.info('table was deleted')
                break
            status = resp.attributes['Table']['TableStatus']
            if status == 'DELETING':
                logging.info('deleting...')
            else:
                logging.error(' unexpected status')
                pdb.set_trace()

    resp = yield gen.Task( db.create_table, table_name, 'id' )
    if resp.code == 200:
        while True:
            resp = yield gen.Task( db.describe_table, table_name )
            status = resp.attributes['Table']['TableStatus']
            if status == 'ACTIVE':
                break
            logging.info('resp %s' % status)
    logging.info('table active!')
    callback(True)

@gen.engine
def test_items():
    table_name = 'FooTable'
    resp = yield gen.Task( db.put_item, table_name, { 'id': { 'S': '2989823' } } )
    if resp.error:
        logging.error('error doing thing %s' % resp)
        raise StopIteration

    logging.info('got resp %s' % resp.attributes)
    resp = yield gen.Task( db.get_item, table_name, '2989823' )

    if resp.error:
        logging.error('error doing 2nd thing %s' % resp)
        raise StopIteration
    #pdb.set_trace()
    #
    

#ioloop.add_callback( basic )
#ioloop.add_callback( test_tables )
ioloop.add_callback( test_items )
ioloop.start()

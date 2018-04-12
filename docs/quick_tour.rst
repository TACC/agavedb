Quick Tour
==========

An implicit assumption is that you have an existing TACC.cloud client set up
using AgavePy or the TACC Cloud CLI. Install AgaveDB from PyPi:

``pip install agavedb``

Start coding. AgaveDB doesn't have a CLI *at present*.


.. code-block:: pycon

    >>> from agavedb import AgaveKeyValStore, Agave
    >>> ag = Agave.restore()
    >>> db = AgaveKeyValStore(ag, prefix="testing")
    >>> db.set('key1', 'value1')
    'key1'
    >>> db.set('key2', 'value2')
    'key2'
    >>> db.set('key3', 'value4')
    True
    >>> db.setacl('key3', {'username': 'taco', 'permission': {'read': True, 'write': True}}')
    True
    >>> db.setacl('key3', {'username': 'world', 'permission': {'read': True, 'write': False}}')
    True
    >>> db.getacls('key3')
    [{'username': 'matt', 'permission': {'read': True, 'write': True}}, {'username': 'taco', 'permission': {'read': True, 'write': True}}, {'username': 'world', 'permission': {'read': True, 'write': False}}]
    >>> db.getacls('key3', 'taco')
    [{'username': 'taco', 'permission': {'read': True, 'write': True}}]
    >>> db.setacl('key3', {'username': 'taco', 'permission': {'read': True, 'write': False}}')
    True
    >>> db.getacls('key3', 'taco')
    [{'username': 'taco', 'permission': {'read': True, 'write': False}}]
    >>> db.remacl('key3', 'taco')
    True
    >>> db.getacls('key3', 'taco')
    # Inherits +read from the world user
    [{'username': 'taco', 'permission': {'read': True, 'write': False}}]
    >>> db.get('key1')
    u'value1'
    >>> db.set('key1', 'value3')
    'key1'
    >>> db.get('key1')
    u'value3'
    >>> db.getall()
    [u'key1', u'key2', u'key3']
    >>> db.rem('key1')
    True
    >>> db.getall()
    [u'key2', u'key3']
    >>> db.set(db.genid(), 'hello world')
    'MZgY69k1ZMd8'
    >>> db.get('MZgY69k1ZMd8')
    u'hello world'
    >>> db.deldb()
    True
    >>> db.getall()
    []


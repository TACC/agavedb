<h1 id="agavedb.keyval">AgaveDB</h1>

AgaveDB is multiuser-aware key/value store built using the Agave metadata web service API. 

The library interface is modeled on [pickledb](https://pythonhosted.org/pickleDB/), which, in turn is
inspired by Redis. Eventually, it will support Agave-based permissions and sharing. If you need a more
document-oriented solution, you can utilize the underlying Agave `metadata` service.

<h2 id="example">Using AgaveDB</h2>

An implicit assumption is that you have an existing client set up using AgavePy or the TACC Cloud CLI. 

Installation is simple: `pip install agavedb`. Then, start coding. AgaveDB doesn't have a CLI at present. 

```python
>>> from agavedb import AgaveKeyValStore, Agave
>>> ag = Agave.restore()
>>> db = AgaveKeyValStore(ag)
>>> db.set('key1', 'value1')
'key1'
>>> db.set('key2', 'value2')
'key2'
>>> db.set('key3', 'value4')
True
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
```

<h2 id="keys-values">About Keys and Values</h2>

<h3 id="keys">Keys</h3>

AgaveDB keys are strings. You have a good degree of flexibility in naming them but there are rules:

* Minimum key length is 4 characters. Really short keys aren't necessary. You will probably thank yourself for writing `user:1001:bugreports` instead of `u1001bg` when it comes time to debug or maintain our code. The added space and memory requirement is trivial. 
* Maximum key length is 512 characters, but such long keys aren't a great idea because they will consume memory and will be slow to retrieve. Consider using a hash (such as SHA1) to represent a larger value. 
* Schemas are good. Examples include `object-type:id` and `user:1001`. Dots, dashes, and underscores are often used as separators.
* Whitespace is not allowed in keynames nor are the characters `/` and `#`

<h3 id="values">Values</h3>

AgaveDB values can be strings (or Unicode) or numeric values. Formally, this is validated by checking whether a value an instance of Python's `basestring` or `numbers.Number` primitives. Support for lists, dicts, and tuples will be added in future releases. The maximum size for an AgaveDB value is currently 4096 bytes. 

<h3 id="apidocs">API Documentation</h3>

API docs [are here](docs/api.md)

<h3 id="apidocs">Tests</h3>

Tests are implemented using `pytest`. Usage documentation is in the [tests folder](agavedb/tests/README.md)

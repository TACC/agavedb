<h1 id="agavedb.keyval">agavedb.keyval</h1>


AgaveDB is multiuser-aware key/value store built using the Agave metadata web service API.

The library interface is modeled on pickledb, which is inspired by Redis. Eventually, it will support Agave-based permissions and sharing. If you need a more
document-oriented solution, you can utilize the underlying Agave `metadata` service.

Usage:
```python
from agavedb import AgaveKeyValStore
```

<h2 id="agavedb.keyval.AgaveKeyValStore">AgaveKeyValStore</h2>

```python
AgaveKeyValStore(self, agaveClient)
```
An AgaveKeyValStore instance. Requires an active Agave client
<h3 id="agavedb.keyval.AgaveKeyValStore.set">set</h3>

```python
AgaveKeyValStore.set(self, key, value)
```
Set the string or numeric value of a key
<h3 id="agavedb.keyval.AgaveKeyValStore.get">get</h3>

```python
AgaveKeyValStore.get(self, key)
```
Get the value of a key
<h3 id="agavedb.keyval.AgaveKeyValStore.deldb">deldb</h3>

```python
AgaveKeyValStore.deldb(self)
```
Delete all user-owned keys
<h3 id="agavedb.keyval.AgaveKeyValStore.getall">getall</h3>

```python
AgaveKeyValStore.getall(self)
```
Return a list of all keys user owns or has access to
<h3 id="agavedb.keyval.AgaveKeyValStore.create_key_name">create_key_name</h3>

```python
AgaveKeyValStore.create_key_name(cls)
```
Create a unique, human-friendly key name
<h3 id="agavedb.keyval.AgaveKeyValStore.rem">rem</h3>

```python
AgaveKeyValStore.rem(self, key)
```
Delete a key (assuming it is owned by the user)

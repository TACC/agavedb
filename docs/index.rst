.. AgaveDB documentation master file, created by
   sphinx-quickstart on Mon Feb 19 16:35:12 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

AgaveDB
=======

A multiuser-aware key/value store built using the Agave metadata API

The library interface is modeled on pickledb_, which is inspired by Redis_. 
Eventually, it will support Agave-based permissions and sharing. If you need a
more document-oriented solution, you can utilize the underlying Agave API
metadata service_.

**Usage:**

.. code-block:: python
   
   from agavedb import AgaveKeyValStore, Agave
   ag = Agave.restore()
   db = AgaveKeyValStore(ag)
   db.set('keyname', 'value')

.. automodule:: agavedb
    :members:

.. toctree::
   :maxdepth: 2
 
   quick_tour.rst
   keys_values.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`

.. _pickledb: https://pythonhosted.org/pickleDB/
.. _Redis: https://redis.io/
.. _service: http://developer.tacc.cloud/docs/guides/metadata/introduction.html

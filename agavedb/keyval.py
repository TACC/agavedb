"""
AgaveDB is multiuser-aware key/value store built using the Agave metadata web service API.

The library interface is modeled on pickledb, which is inspired by Redis. Eventually, it will support Agave-based permissions and sharing. If you need a more
document-oriented solution, you can utilize the underlying Agave `metadata` service.

Usage:
```python
from agavedb import AgaveKeyValStore
```
"""

from attrdict import AttrDict
from agavepy.agave import Agave
import re
import json
import logging
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
import uniqueid

_SEP = '/'
_PREFIX = '_agkvs_v1'
_TTL = 86400
_MAX_VAL_BYTES = 4096
_MIN_KEY_BYTES = 4
_MAX_KEY_BYTES = 512
_RE_KEY_NAMES = re.compile('^[\S]+$', re.UNICODE)

# TODO: Implement list and dict methods
# TODO: Implement permissions management


class AgaveKeyValStore(object):

    """An AgaveKeyValStore instance. Requires an active Agave client"""

    def __init__(self, agaveClient):
        '''Initialize class with a valid Agave API client'''
        self.client = agaveClient
        self.default_ttl = _TTL
        FORMAT = "[%(levelname)s] %(asctime)s: %(message)s"
        DATEFORMAT = "%Y-%m-%dT%H:%M:%SZ"
        self.logging = logging.getLogger('AgaveKeyValStore')
        stderrLogger = logging.StreamHandler()
        stderrLogger.setFormatter(
            logging.Formatter(FORMAT, datefmt=DATEFORMAT))
        self.logging.addHandler(stderrLogger)

    def set(self, key, value):
        '''Set the string or numeric value of a key'''
        try:
            return self._set(key, value)
        except Exception as e:
            self.logging.error("set({}, {}): {}".format(key, value, e))
            return None

    def get(self, key):
        '''Get the value of a key'''
        try:
            return self._get(key)['value']
        except Exception as e:
            self.logging.error("get: {}".format(e))
            return None

    def getall(self):
        '''Return a list of all keys user owns or has access to'''
        namespaces = False
        try:
            return self._getall(namespaces)
        except Exception as e:
            self.logging.error("Error in getall: {}".format(e))
            return []

    def rem(self, key):
        '''Delete a key (assuming it is owned by the user)'''
        try:
            return self._rem(key)
        except Exception as e:
            print("Error in rem: {}".format(e))
            return False

    def deldb(self):
        '''Delete all user-owned keys'''
        try:
            return self._remall()
        except Exception as e:
            print("Error in deldb: {}".format(e))
            return False

    def _namespace(self, keyname):
        """Namespaces a key

        e.g.) keyname => _agavedb/keyname#username
        """
        if self._key_is_valid(keyname):
            _keyname = keyname
            _keyname = _PREFIX + _SEP + _keyname + \
                '#' + self._username()
            return _keyname
        else:
            raise ValueError("Invalid key name: {}".format(keyname))
            return None

    def _rev_namespace(self, fullkeyname, removeusername=True):
        """Reverse namespacing of a key's internal representation.

        e.g.) _agavedb/keyname#username => keyname
        """
        assert isinstance(fullkeyname, basestring), \
            "key type must be string or unicode (type: {})".format(
                self._type(fullkeyname))

        _prefix = _PREFIX + _SEP
        keyname = fullkeyname
        if keyname.startswith(_prefix):
            keyname = keyname[len(_prefix):]

        if removeusername:
            _suffix = '#' + self._username()
            if keyname.endswith(_suffix):
                keyname = keyname[:(-1 * len(_suffix))]

        return keyname

    def _slugify(self, value, allow_unicode=False):
        """
        Convert a string to a conservatively URL-safe version

        Converts to ASCII if 'allow_unicode' is False. Converts
        whitespace to hyphens. Removes characters that aren't
        alphanumerics, underscores, or hyphens. Converts to
        lowercase. Strips leading and trailing whitespace.
        """
        import unicodedata
        value = unicode(value)
        if allow_unicode:
            value = unicodedata.normalize('NFKC', value)
        else:
            value = unicodedata.normalize(
                'NFKD', value).encode('ascii', 'ignore').decode('ascii')
        value = re.sub(r'[^\w\s-]', '', value).strip().lower()
        value = re.sub(r'[-\s]+', '-', value)
        return value

    def _type(self, obj):
        '''Return the type name of a Python object'''
        return type(obj).__name__

    def _username(self):
        '''Return the current Agave API username'''
        try:
            return self.__get_api_username()
        except Exception as e:
            raise Exception("Unable to establish username: {}".format(e))
            return None

    def _get(self, key):
        '''Get value by key name.'''
        shares = False
        key_name = self._namespace(key)
        username = self._username()
        # An Agave metadata object, not yet the value
        if shares:
            _regex = "^{}/{}#".format(_PREFIX, key)
            query = json.dumps({'name': {'$regex': _regex, '$options': 'i'}})
        else:
            query = json.dumps({'name': key_name})

        key_objs = self.client.meta.listMetadata(q=query)
        key_objs_owner = []
        key_objs_other = []
        for key_obj in key_objs:
            if key_obj['owner'] == username:
                key_objs_owner.append(key_obj)
            else:
                key_objs_other.append(key_obj)
        key_objs_merged = key_objs_owner + key_objs_other
        if len(key_objs_merged) > 0:
            return key_objs_merged[0]
        else:
            raise KeyError("No such key: {}".format(key))

    def _set(self, key, value):
        '''Update/write value to a key'''
        key_name = self._namespace(key)
        key_uuid = None

        if not self._value_is_valid(value):
            raise ValueError(
                "Key type for {} not valid (type: {})".format(
                    key, self._type(value)))
            return None

        key_uuid_obj = {}
        try:
            key_uuid_obj = self._get(key)
            key_uuid = key_uuid_obj['uuid']
        except KeyError:
            self.logging.debug("Key {} doesn't yet exist".format(key))
            pass

        current_time = int(time.time())
        if '_created' in key_uuid_obj:
            created_t = key_uuid_obj['_created']
            expires_t = current_time + _TTL
        else:
            created_t = current_time
            expires_t = created_t + _TTL

        try:
            value = unicode(value)
        except Exception as e:
            self.logging.error(
                "Couldn't coerce {} to unicode: {}".format(value, e))
            return None

        try:
            value = self._stringify(value)
        except Exception as e:
            self.logging.error(
                "Couldn't stringify {}: {}".format(value, e))
            return None

        # our metadata record with timestamps
        meta = json.dumps({'name': key_name,
                           'value': value,
                           '_created': created_t,
                           '_expires': expires_t,
                           '_ttl': _TTL})

        if key_uuid is None:
            # Create
            try:
                self.client.meta.addMetadata(body=meta)
            except Exception as e:
                self.logging.error("Error creating key {}: {}".format(key, e))
                return None
        else:
            # Update
            try:
                self.client.meta.updateMetadata(uuid=key_uuid, body=meta)
            except Exception as e:
                self.logging.error("Error updating key {}: {}".format(key, e))
                return None

        return key

    def _getall(self, namespace=False, sorted=True, uuids=False):
        '''Fetch and return all keys visible to the user'''
        all_keys = []
        _regex = "^{}/*".format(_PREFIX)
        query = json.dumps({'name': {'$regex': _regex, '$options': 'i'}})
        # collection of Agave metadata objects
        key_objs = self.client.meta.listMetadata(q=query)
        for key_obj in key_objs:
            if uuids:
                all_keys.append(key_obj['uuid'])
            elif namespace:
                all_keys.append(key_obj['name'])
            else:
                all_keys.append(self._rev_namespace(key_obj['name']))

        if sorted:
            all_keys.sort()

        return all_keys

    def _rem(self, key):
        '''Delete a key from a user's namespace'''
        key_uuid = None
        try:
            key_uuid = self._get(key)
            key_uuid = key_uuid['uuid']
        except KeyError:
            raise KeyError("No such key: {}".format(key))
            return False
        except Exception as e:
            self.logging.info("Error validating key {}: {}".format(key, e))
            return False

        try:
            self._rem_by_uuid(key_uuid)
        except Exception as e:
            self.logging.debug("Error deleting key {}".format(key))
            return False
        return True

    def _rem_by_uuid(self, key_uuid):
        '''Delete key by its UUID'''
        try:
            self.client.meta.deleteMetadata(uuid=key_uuid)
        except Exception:
            self.logging.debug(
                "Error deleting key with UUID {}".format(key_uuid))
            return False
        return True

    def _remall(self):
        '''Remove all the user's keys'''
        try:
            key_list = self._getall(uuids=True)
            for key_uuid in key_list:
                self._rem_by_uuid(key_uuid)
        except Exception:
            self.logging.error("Error deleting all keys")
            return False
        return True

    def _value_is_valid(self, value):
        '''Value must be a string. Others may be supported later.'''
        assert isinstance(value, basestring), \
            "value must be string or unicode (type: {})".format(
                self._type(value))
        assert len(value) <= _MAX_VAL_BYTES, \
            "value must be <= {} (length: {})".format(len(value))
        return True

    def _key_is_valid(self, key):
        '''Enforce key naming restrictions'''

        # type
        assert isinstance(key, basestring), \
            "key type must be string or unicode (type: {})".format(
                self._type(key))

        # character set
        assert _RE_KEY_NAMES.match(key), \
            "key may only contain non-whitespace characters"
        assert _SEP not in key, "key may not contain '{}'".format(_SEP)
        assert '#' not in key, "key may not contain #"

        # length
        assert len(key) <= _MAX_KEY_BYTES, \
            "key must be <= {} characters (length: {})".format(
                _MAX_KEY_BYTES, len(key))
        assert len(key) >= _MIN_KEY_BYTES, \
            "key must be >= {} characters (length: {})".format(
                _MIN_KEY_BYTES, len(key))

        return True

    def _stringify(self, value):
        '''Coerce a value to a string type before sending to MongoDB'''
        return '"' + value + '"'

    @classmethod
    def create_key_name(cls):
        '''Create a unique, human-friendly key name'''
        return uniqueid.get_id()

    def __get_api_username(self):
        '''Determine username'''
        if os.environ.get('_abaco_username'):
            return os.environ.get('_abaco_username')
        elif self.client.username is not None:
            return self.client.username
        else:
            print("No username could be determined")
            return None

    def __get_api_token(self):
        '''Determine API access_token'''
        if os.environ.get('_abaco_access_token'):
            return os.environ.get('_abaco_access_token')
        elif self.client.token.token_info.get('access_token') is not None:
            return self.client.token.token_info.get('access_token')
        else:
            print("Failed to retrieve API access_token")
            return None

    def __get_api_server(self):
        '''Determine API server'''
        if os.environ.get('_abaco_api_server'):
            return os.environ.get('_abaco_api_server')
        elif self.client.token.api_server is not None:
            return self.client.token.api_server
        else:
            print("Returning hard-coded value for API server")
            return 'https://api.sd2e.org'


def main():
    ag = Agave.restore()
    kvs = AgaveKeyValStore(ag)

    print("Test namespacing")
    print(kvs._namespace("abc123"))
    print(kvs._rev_namespace("_agkvs_v1/abc123#sd2eadm"))
    print(kvs._rev_namespace("_agkvs_v1/abc123#sd2eadm", False))

    print("Test simple set/get")
    print(kvs.set('abc123', 'value34567'))
    print(kvs.get('abc123'))
    # non-existent key
    print(kvs.get('XXXX'))

    # set some more key/values
    print(kvs.set('org.sd2e.reactors', 'DFGHJKJHGFDSASDFGH'))
    print(kvs.set('abc345', 'value34567'))
    print(kvs.set('abc456', 'value34567'))

    print("Test key properties enforcement")
    # min length
    kvs.set('xyz', 'SDFGHJKJHGFDSDFGHJK')
    # type
    kvs.set(123, 456)
    kvs.set(None, 456)

    print("Test value type enforcement")
    kvs.set('abc789', {'name': 'value'})
    kvs.set('abc789', ('new york', 'los angeles'))
    kvs.set('abc789', [1, 2, 3])
    kvs.set('abc789', None)
    kvs.set('abc789', kvs)

    print("Test get all keys")
    print(kvs.getall())

    print("Test key remove")
    kvs.rem('abc123')
    # key abc123 should be done
    print(kvs.getall())

    # print("Test remove all keys")
    # kvs.deldb()
    # empty list
    print(kvs.getall())

    print("Test adding string w number at beginning")
    print(kvs.set('numstring', '6G5x4jqPBvBJy'))
    print(kvs.get('numstring'))

    print("Test adding numerical values")
    print(kvs.set('numbers.Number.6', '6'))
    print(kvs.get('numbers.Number.6'))
    print(kvs.set('numbers.Number.6', 6))
    print(kvs.get('numbers.Number.6'))

    # print(kvs.set('numbers_Number_6', 6))
    # print(kvs.get('numstring_Number_6'))

    print("Generate Unique ID")
    print(kvs.create_key_name())


if __name__ == '__main__':
    main()

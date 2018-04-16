"""
AgaveDB

Multiuser-aware key/value store built atop the Agave metadata API.

The library interface is modeled on pickledb, which is inspired by Redis, but
with the addition of simple access control list via the Agave permisisons
model. If you need document-oriented solution, you should use the actual
Agave metadata service rather than AgaveDB.

Usage:
```python
from agavedb import AgaveKeyValStore, Agave

db = AgaveKeyValStore(Agave.restore())
```
"""
from __future__ import print_function
from __future__ import absolute_import
from future.standard_library import install_aliases
install_aliases()

from past.builtins import basestring
from agavepy.agave import Agave, AgaveError

import base64
import re
import json
import logging
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
# from . import uniqueid
import uniqueid

_SEP = '/'
_PREFIX = '_agkvs_v2'
_TTL = 86400
_MAX_VAL_BYTES = 4096
_MIN_KEY_BYTES = 4
_MAX_KEY_BYTES = 512
_RE_KEY_NAMES = re.compile('^[\S]+$', re.UNICODE)
VALID_PEMS = ['read', 'write', 'execute']
VALID_ROLE_USERNAMES = ['world', 'public']
# TODO: Implement list and dict methods
# DONE: Implement permissions management


class AgaveKeyValStore(object):

    """An AgaveKeyValStore instance. Requires an active Agave client"""

    def __init__(self, agaveClient, prefix=_PREFIX, loglevel='INFO'):
        """
        Initialize a AgaveKeyValStore object

        Positional parameters:
        agaveClient - an initialaized Agave object

        Keyword parameters:
        prefix - str - Optional override for key prefix
        loglevel - Set the logging level. DEBUG is good for diagnosing issues.

        Returns:
        - AgaveKeyValStore
        """
        self.client = agaveClient
        self.default_ttl = _TTL
        FORMAT = "%(asctime)s [%(levelname)s] - %(message)s"
        DATEFORMAT = "%Y-%m-%dT%H:%M:%SZ"
        self.logging = logging.getLogger('AgaveKeyValStore')
        self.logging.setLevel(loglevel)
        stderrLogger = logging.StreamHandler()
        stderrLogger.setFormatter(
            logging.Formatter(FORMAT, datefmt=DATEFORMAT))
        self.logging.addHandler(stderrLogger)
        self.prefix = prefix

    def set(self, key, value):
        '''Set the string or numeric value of a key'''
        try:
            return self._set(key, value)
        except Exception as e:
            self.logging.error("set({}, {}): {}".format(key, value, e))
            return None

    def setacl(self, key, acl):
        """
        Set an ACL on a given key

        Positional parameters:
        key - str - Key to manage permissions on
        acl - dict - Valid permissions object

        {'read': bool, 'write': bool}

        Returns:
        Boolean True on success, and Exception + False on failure
        """
        try:
            self.validate_acl(acl)
            return self._setacl(key, acl)
        except Exception as e:
            self.logging.debug(
                "Failed to set ACl({}, {}): {}".format(key, acl, e))
            return False

    def remacl(self, key, user):
        """
        Remove an ACL on a key for a given user

        Positional parameters:
        key - str - Key to manage permissions on
        user - str - Username whose ACL should be dropped

        Returns:
        Boolean True on success, and Exception + False on failure
        """
        acl = {'username': user,
               'permission': {'read': None, 'write': None, 'execute': None}}
        try:
            return self._setacl(key, acl)
        except Exception as e:
            self.logging.debug(
                "Failed to remove ACL({}, {}): {}".format(key, user, e))
            return False

    def getacls(self, key, user=None):
        """
        Get the ACLs for a given key

        Keywork parameters:
        user - str - Return ACL only for this username
        """
        try:
            return self._getacls(key, user)
        except Exception as e:
            self.logging.debug("Failed to getacls: {}".format(e))
            return []

    def get(self, key):
        '''Get the value of a key'''
        try:
            return self._get(key)['value']
        except Exception as e:
            self.logging.debug("Failed to get: {}".format(e))
            return None

    def getall(self, sorted=True):
        '''Return a list of all keys user owns or has access to'''
        try:
            return self._getall(sorted=sorted, namespace=False)
        except Exception as e:
            self.logging.debug("Failed to getall: {}".format(e))
            return []

    def rem(self, key):
        '''Delete a key (assuming it is owned by the user)'''
        try:
            return self._rem(key)
        except Exception as e:
            self.logging.debug("Failed to rem: {}".format(e))
            return False

    def deldb(self):
        '''Delete all user-owned keys'''
        try:
            return self._remall()
        except Exception as e:
            self.logging.debug("Failed to deldb: {}".format(e))
            return False

    def _namespace(self, keyname):
        """Namespaces a key

        e.g.) keyname => _agavedb/keyname#username
        """
        if self._key_is_valid(keyname):
            _keyname = base64.urlsafe_b64encode(keyname.encode()).decode()
            _keyname = self.prefix + _SEP + _keyname + '#' + self._username()
            return str(_keyname)
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

        _prefix = self.prefix + _SEP
        keyname = fullkeyname
        if keyname.startswith(_prefix):
            keyname = keyname[len(_prefix):]

        # if removeusername:
        _suffix = '#' + self._username()
        if keyname.endswith(_suffix):
            keyname = keyname[:(-1 * len(_suffix))]

        # print(keyname)
        if not isinstance(keyname, bytes):
            keyname = keyname.encode()

        keyname_tmp = ''
        keyname_tmp = base64.urlsafe_b64decode(keyname)
        keyname = keyname_tmp

        # Python2/3 compatible coercion to a "stringy" key name
        if isinstance(keyname, bytes):
            if not removeusername:
                keyname = keyname + _suffix.encode()
            return keyname.decode('utf-8')
        else:
            if not removeusername:
                keyname = keyname + _suffix
            return str(keyname)

    def _slugify(self, value, allow_unicode=False):
        """
        Convert a string to a conservatively URL-safe version

        Converts to ASCII if 'allow_unicode' is False. Converts
        whitespace to hyphens. Removes characters that aren't
        alphanumerics, underscores, or hyphens. Converts to
        lowercase. Strips leading and trailing whitespace.
        """
        import unicodedata
        value = str(value)
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
            _regex = "^{}/{}#".format(self.prefix, key)
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
            value = str(value)
        except Exception as e:
            self.logging.debug(
                "Couldn't coerce {} to unicode: {}".format(value, e))
            return None

        try:
            value = self._stringify(value)
        except Exception as e:
            self.logging.debug(
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
                self.logging.debug("Error creating key {}: {}".format(key, e))
                return None
        else:
            # Update
            try:
                self.client.meta.updateMetadata(uuid=key_uuid, body=meta)
            except Exception as e:
                self.logging.debug("Error updating key {}: {}".format(key, e))
                return None

        return key

    def _setacl(self, key, acl):
        '''Add or update an ACL to a key'''
        key_uuid = None
        key_uuid_obj = {}
        try:
            key_uuid_obj = self._get(key)
            key_uuid = key_uuid_obj['uuid']
        except KeyError:
            self.logging.debug("Key {} not found".format(key))
            raise KeyError("Key {} not found".format(key))

        pem = self.to_text_pem(acl)
        meta = json.dumps(pem, indent=0)
        try:
            self.client.meta.updateMetadataPermissions(
                uuid=key_uuid, body=meta)
            return True
        except Exception as e:
                self.logging.debug(
                    "Error setting ACL for {}: {}".format(key, e))
                return False

    def _getacls(self, key, user=None):
        '''List ACLs on a given key'''
        key_uuid = None
        key_uuid_obj = {}
        acls = []

        try:
            key_uuid_obj = self._get(key)
            key_uuid = key_uuid_obj['uuid']
        except KeyError:
            self.logging.debug("Key {} not found".format(key))
            raise KeyError("Key {} not found".format(key))
        try:
            resp = self.client.meta.listMetadataPermissions(uuid=key_uuid)
            for acl in resp:
                formatted_acl = {'username': acl.get('username'),
                                 'permission': acl.get('permission')}
                if user is None:
                    acls.append(formatted_acl)
                else:
                    if user == acl.get('username'):
                        acls.append(formatted_acl)
                    # show the user is inheriting world acl
                    elif 'world' == acl.get('username'):
                        acls.append(formatted_acl)
        except Exception as e:
            self.logging.debug(
                "Failed getting ACLs for for {}: {}".format(key, e))

        return acls

    def _getall(self, sorted=True, namespace=False, uuids=False):
        '''Fetch and return all keys visible to the user'''
        all_keys = []
        _regex = "^{}/*".format(self.prefix)
        query = json.dumps({'name': {'$regex': _regex, '$options': 'i'}})
        # collection of Agave metadata objects
        key_objs = self.client.meta.listMetadata(q=query)
        for key_obj in key_objs:
            if uuids:
                tmp_uuid = key_obj['uuid']
                if isinstance(tmp_uuid, bytes):
                    tmp_uuid = tmp_uuid.decode('utf-8')
                all_keys.append(tmp_uuid)
            elif namespace:
                temp_key = self._rev_namespace(
                    key_obj['name'], removeusername=namespace)
                all_keys.append(temp_key)
            else:
                temp_key = self._rev_namespace(key_obj['name'])
                all_keys.append(temp_key)

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
            self.logging.debug("Error validating key {}: {}".format(key, e))
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
            self.logging.debug("Error deleting all keys")
            return False
        return True

    def _value_is_valid(self, value):
        '''Value must be a string. Others may be supported later.'''
        assert isinstance(value, basestring), \
            "value must be str-like (type: {})".format(
                self._type(value))
        assert len(value) <= _MAX_VAL_BYTES, \
            "value must be <= {} bytes (length: {})".format(len(value))
        return True

    def _key_is_valid(self, key):
        '''Enforce key naming restrictions'''

        # type
        assert isinstance(key, basestring), \
            "key type must be str-like type (type: {})".format(
                self._type(key))

        # character set
        assert _RE_KEY_NAMES.match(key), \
            "key may only contain non-whitespace characters"

        # now that the key value is base64 encoded before namespacing, this
        # is no longer required
        # assert _SEP not in key, "key may not contain '{}'".format(_SEP)
        # assert '#' not in key, "key may not contain #"

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

    @classmethod
    def to_text_pem(cls, acl):
        pem = {"username": acl.get('username')}
        permission = acl.get('permission')
        perm_str = u'NONE'
        r, w, x = permission.get('read', False), \
            permission.get('write', False), \
            permission.get('execute', False)

        if r:
            perm_str = u'READ'
        if w:
            perm_str = u'READ_WRITE'
        if x:
            perm_str = u'READ_EXECUTE'
        if r and w:
            perm_str = u'READ_WRITE'
        if r and x:
            perm_str = u'READ_EXECUTE'
        if r and w and x:
            perm_str = u'ALL'

        pem['permission'] = perm_str
        return pem

    @classmethod
    def from_text_pem(cls, pem):
        acl = {"username": pem.get('username')}
        permission = pem.get('permission').upper()
        perm_dict = {'read': False, 'write': False, 'execute': False}

        if u'ALL' in permission:
            perm_dict = {'read': True, 'write': True, 'execute': True}
        elif u'NONE' in permission:
            perm_dict = {'read': False, 'write': False, 'execute': False}
        else:
            if u'READ' in permission:
                perm_dict['read'] = True
            if u'WRITE' in permission:
                perm_dict['write'] = True
                perm_dict['read'] = True
            if u'EXECUTE' in permission:
                perm_dict['execute'] = True
                perm_dict['read'] = True
        acl['permission'] = perm_dict
        return acl

    @classmethod
    def validate_acl(cls, acl, permissive=False):
        """
        Validate an ACL object as a dict

        Failure raises Exception unless permissive is True
        * Does not validate that username exists
        """
        err = 'Invalid ACL: {}'
        try:
            assert isinstance(acl, dict), "Not a dict"
            assert 'username' in acl and 'permission' in acl, \
                "Both username and permission are required"
            assert isinstance(acl['permission'], dict), \
                "Permission must be a dict"
            assert isinstance(acl['username'], basestring), \
                "Username must be string or unicode"
            assert set(acl['permission'].keys()) == set(VALID_PEMS) or \
                set(acl['permission'].keys()) <= set(VALID_PEMS), \
                "Valid permission types are {} not {}".format(
                    VALID_PEMS, list(acl['permission'].keys()))
            for p in acl['permission']:
                assert isinstance(acl['permission'][p], bool), \
                    "Only Boolean values allowed for permission values"
            return True
        except Exception as exc:
            if permissive is True:
                return False
            else:
                raise AgaveError(err.format(exc))

    def __get_api_username(self):
        '''Determine username'''
        if os.environ.get('_abaco_username'):
            return os.environ.get('_abaco_username')
        elif self.client.username is not None:
            return self.client.username
        else:
            self.logging.debug("No username could be determined")
            return None

    def __get_api_token(self):
        '''Determine API access_token'''
        if os.environ.get('_abaco_access_token'):
            return os.environ.get('_abaco_access_token')
        elif self.client.token.token_info.get('access_token') is not None:
            return self.client.token.token_info.get('access_token')
        else:
            self.logging.debug("Failed to retrieve API access_token")
            return None

    def __get_api_server(self):
        '''Determine API server'''
        if os.environ.get('_abaco_api_server'):
            return os.environ.get('_abaco_api_server')
        elif self.client.token.api_server is not None:
            return self.client.token.api_server
        else:
            self.logging.debug("Returning hard-coded value for API server")
            return 'https://api.sd2e.org'


def to_unicode(input):
    '''Py2/Py3 unicode encoder'''
    if isinstance(input, bytes):
        input = str(input)
    return input.encode().decode('utf-8')

# def to_unicode(input):
#     '''Trivial unicode encoder'''
#     if type(input) != unicode:
#         input = input.decode('utf-8')
#         return input
#     else:
#         return input


def main():
    ag = Agave.restore()
    kvs = AgaveKeyValStore(ag)

    print(kvs.getall())

if __name__ == '__main__':
    main()

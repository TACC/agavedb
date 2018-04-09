#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Usage: See bundled README.md

from future.standard_library import install_aliases
install_aliases()
from urllib.parse import urlencode, quote

from builtins import str

import json
import os
import pytest
import random
import uuid

from agavepy.agave import Agave
from agavedb import AgaveKeyValStore, uniqueid

from . import testdata

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope='session')
def credentials():
    '''
    Load credentials for testing session

    Order: user credential store, test file, env
    '''
    credentials = {}
    # credential store
    ag_cred_store = os.path.expanduser('~/.agave/current')
    if os.path.exists(ag_cred_store):
        tempcred = json.load(open(ag_cred_store, 'r'))
        credentials['apiserver'] = tempcred.get('baseurl', None)
        credentials['username'] = tempcred.get('username', None)
        credentials['password'] = tempcred.get('password', None)
        credentials['apikey'] = tempcred.get('apikey', None)
        credentials['apisecret'] = tempcred.get('apisecret', None)
        credentials['token'] = tempcred.get('access_token', None)
        credentials['refresh_token'] = tempcred.get('refresh_token', None)
        credentials['verify_certs'] = tempcred.get('verify', None)
        credentials['client_name'] = tempcred.get('client_name', None)
        credentials['tenantid'] = tempcred.get('tenantid', None)
    # test file
    credentials_file = os.environ.get('creds', 'test_credentials.json')
    print(("Loading file: {}".format(credentials_file)))
    if os.path.exists(credentials_file):
        credentials = json.load(open(
            os.path.join(HERE, credentials_file), 'r'))
    # environment
    for env in ('apikey', 'apisecret', 'username', 'password',
                'apiserver', 'verify_certs', 'refresh_token',
                'token', 'client_name'):
        varname = '_AGAVE_' + env.upper()
        if os.environ.get(varname, None) is not None:
            credentials[env] = os.environ.get(varname)
            print("Loaded {} from env".format(env))

    return credentials


@pytest.fixture(scope='session')
def agave(credentials):
    ag = Agave(username=credentials.get('username'),
               password=credentials.get('password', None),
               client_name=credentials.get('client_name', None),
               api_server=credentials.get('apiserver'),
               api_key=credentials.get('apikey'),
               api_secret=credentials.get('apisecret'),
               token=credentials.get('token', None),
               refresh_token=credentials.get('refresh_token', None),
               verify=True)
    return ag


@pytest.fixture(scope='session')
def keyprefix():
    return uniqueid.get_id()


@pytest.fixture(scope='session')
def keyvalstore(agave, keyprefix):
    kvs = AgaveKeyValStore(agave, prefix=keyprefix)
    return kvs


@pytest.fixture(scope='session')
def test_data(credentials):
    return testdata.TestData(credentials).data()


def test_prefix(keyvalstore, keyprefix):
    '''Test that prefix has been overridden'''
    assert keyvalstore.prefix == keyprefix


def test_key_valid(keyvalstore, credentials, test_data):

    # types
    invalid_types = test_data['key_valid']['types']
    for test_key in invalid_types:
        with pytest.raises(AssertionError) as excinfo:
            keyvalstore._key_is_valid(test_key)
        assert 'string or unicode' in str(excinfo.value)

    # length check
    invalid_lengths = test_data['key_valid']['lengths']
    for test_key in invalid_lengths:
        with pytest.raises(AssertionError) as excinfo:
            keyvalstore._key_is_valid(test_key)
        assert 'length:' in str(excinfo.value)

    # non-whitespace characters
    invalid_whitespace = test_data['key_valid']['whitespace']
    for test_key in invalid_whitespace:
        with pytest.raises(AssertionError) as excinfo:
            keyvalstore._key_is_valid(test_key)
        assert 'non-whitespace characters' in str(excinfo.value)

    # banned characters
    banned_chars = test_data['key_valid']['banned']
    for test_key in banned_chars:
        with pytest.raises(AssertionError) as excinfo:
            keyvalstore._key_is_valid(test_key)
        assert 'key may not contain' in str(excinfo.value)


def test_namespace_fwd(keyvalstore, credentials):
    '''_namespace'''
    ns = keyvalstore._namespace('abc123')
    expected = keyvalstore.prefix + '/YWJjMTIz#' + credentials['username']
    assert ns == expected


def test_namespace_rev(keyvalstore, credentials):
    '''_namespace_rev'''
    # with #username extension
    ns = keyvalstore._rev_namespace(
        keyvalstore.prefix + '/abc123#' + credentials['username'], False)
    expected = 'abc123#' + credentials['username']
    assert ns == expected
    # without #username extension
    ns = keyvalstore._rev_namespace(
        keyvalstore.prefix + '/abc123#' + credentials['username'], True)
    expected = 'abc123'
    assert ns == expected


def test_value_valid_type(keyvalstore, credentials):
    '''valid values for keys'''

    # dict
    with pytest.raises(AssertionError) as excinfo:
        keyvalstore._value_is_valid({'name': 'value'})
    assert 'string or unicode' in str(excinfo.value)

    # tuple
    with pytest.raises(AssertionError) as excinfo:
        keyvalstore._value_is_valid(('new york', 'los angeles'))
    assert 'string or unicode' in str(excinfo.value)

    # list
    with pytest.raises(AssertionError) as excinfo:
        keyvalstore._value_is_valid([1, 2, 3])
    assert 'string or unicode' in str(excinfo.value)

    # NoneType
    with pytest.raises(AssertionError) as excinfo:
        keyvalstore._value_is_valid(None)
    assert 'string or unicode' in str(excinfo.value)

    # python obkect
    with pytest.raises(AssertionError) as excinfo:
        keyvalstore._value_is_valid(keyvalstore)
    assert 'string or unicode' in str(excinfo.value)


def test_set_get_rem(keyvalstore, credentials):
    '''test key set/get/delete cycle'''
    key_name = 'keyval-test-' + str(random.randint(10, 99))
    key_valu = '6edd8c34-3aba-46d8-86bf-550db9ffb909'
    set_key_name = keyvalstore.set(key_name, key_valu)
    assert set_key_name == key_name
    get_key_valu = keyvalstore.get(key_name)
    assert get_key_valu == key_valu
    assert keyvalstore.rem(key_name) is True


def test_get_nonexistent(keyvalstore, credentials):
    '''test get on a key that doesn't exist'''
    key_name = uuid.uuid4().hex
    assert keyvalstore.get(key_name) is None


def test_getall(keyvalstore, credentials):
    '''getall - validate that an array is returned'''
    assert isinstance(keyvalstore.getall(), list)


def test_username(keyvalstore, credentials):
    '''verify that agavedb and test view of username is same'''
    assert credentials['username'] == keyvalstore._username()


def test_keys_can_contain_urlchars(keyvalstore, credentials):
    '''tests to address github.com/TACC/agavedb/issues/1'''
    test_keys = ['manifest.json:INSERT:sailfish',
                 u'manifest.json:INSERT:sailfish',
                 quote('manifest.json:INSERT:sailfish'),
                 quote(u'manifest.json:INSERT:sailfish')]
    for key_name in test_keys:
        key_valu = uuid.uuid4().hex
        set_key_name = keyvalstore.set(key_name, key_valu)
        assert set_key_name == key_name
        get_key_valu = keyvalstore.get(key_name)
        assert get_key_valu == key_valu
        assert keyvalstore.rem(key_name) is True


def tests_keys_can_be_uri(keyvalstore, credentials, test_data):
    '''tests to ensure URI are valid keys'''
    test_keys = test_data.get('urlkeys')
    for key_name in test_keys:
        key_valu = uuid.uuid4().hex
        set_key_name = keyvalstore.set(key_name, key_valu)
        assert set_key_name == key_name
        get_key_valu = keyvalstore.get(key_name)
        assert get_key_valu == key_valu
        assert keyvalstore.rem(key_name) is True


def test_deldb(keyvalstore):
    '''getall - validate that an array is returned'''
    keyvalstore.deldb()
    keylist = keyvalstore.getall()
    assert len(keylist) == 0

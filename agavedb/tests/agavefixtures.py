#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Usage: See bundled README.md

from future.standard_library import install_aliases
install_aliases()
from urllib.parse import urlencode, quote
from past.builtins import basestring

import json
import os
import pytest
import random
import uuid

from agavepy.agave import Agave, AgaveError

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PREFIXES = ('AGAVE', '_AGAVE', 'TACC', '_TACC')


@pytest.fixture(scope='session')
def credentials():
    '''
    Load credentials for testing session

    Order: user credential store, test file, env
    '''
    credentials = {}
    # credential store
    # credential store
    if os.environ.get('AGAVE_CACHE_DIR', None) is not None:
        ag_cred_store = os.path.join(
            os.environ.get('AGAVE_CACHE_DIR'), 'current')
    else:
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
    if os.path.exists(credentials_file):
        credentials = json.load(open(
            os.path.join(HERE, credentials_file), 'r'))
    # environment
    for env in ('apikey', 'apisecret', 'username', 'password',
                'apiserver', 'verify_certs', 'refresh_token',
                'token', 'client_name'):
        for vpx in ENV_PREFIXES:
            varname = '_'.join([vpx, env.upper()])
            if os.environ.get(varname, None) is not None:
                credentials[env] = os.environ.get(varname)

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

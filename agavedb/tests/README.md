## To run AgaveDB's tests

1. Provide Agave API credentials. You can use the ones stored in
   $HOME/.agave/current, put them in an agavedb/tests/test_credentials.json
   file following the template, or set environment variables (below).

2. To run the tests, use the following from the `agavedb/tests` directory with
   a Python environment that has requirements.txt installed. This can, and
   probably should, be a pipenv or virtualenv environment.

Run all tests:

```py.test```

Run a single test whose name is <test_name>

```py.test test_agavedb_keyval.py::<test_name>```

Run all tests with <string> in the name.

```py.test -k <string>```

### Examples

```python
py.test test_agavedb_keyval.py::test_key_valid
py.test -k namespace
py.test
```

## Configure an Agave API client using environment variables

The testing code reads from env after looking for disk-based credential stores. This is 
straightforward path for configuring CI services to interact with Agave APIs without
committing secrets to Docker registries or public source repositories. To leverage this,
generate a dedicated testing client using TACC Cloud CLI command `clients-create`, authenticate
to acquire Oauth2 tokens, then configure environment variables in your CI platform with the 
returned values. Here's a worked example:

### Create an API Client

```shell
clients-create -v -N travis_ci_mwvaughn_tacc -u mwvaughn
Password: *******

{
  "description": "",
  "name": "travis_ci_mwvaughn_tacc",
  "consumerKey": "Z1c2eNDRDSONw78215QoAcHzflka",
  "_links": {
    "subscriber": {
      "href": "https://api.tacc.cloud/profiles/v2/mwvaughn"
    },
    "self": {
      "href": "https://api.tacc.cloud/clients/v2/travis_ci_mwvaughn_tacc"
    },
    "subscriptions": {
      "href": "https://api.tacc.cloud/clients/v2/travis_ci_mwvaughn_tacc/subscriptions/"
    }
  },
  "tier": "Unlimited",
  "consumerSecret": "WfHf84wrUeff3iEuUpxA4a",
  "callbackUrl": ""
}
```

### Set Environment Variables

```shell
_AGAVE_APISERVER=https://api.tacc.cloud/
_AGAVE_USERNAME=mwvaughn
_AGAVE_PASSWORD=Pa$zw0rD!
_AGAVE_CLIENT_NAME=travis_ci_mwvaughn_tacc
_AGAVE_APIKEY=Z1c2eNDRDSONw78215QoAcHzflka
_AGAVE_APISECRET=WfHf84wrUeff3iEuUpxA4a
```

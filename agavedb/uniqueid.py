"""
Generate Abaco-style human-readable UUIDs

Uses the hashids library and strong random
number generator. These UUIDs are nearly as
unique as UUID4 but are much more readable.
"""

import uuid
from hashids import Hashids

_HASH_SALT = '97JFXMGWBDaFWt8a4d9NJR7z3erNcAve'


def get_id():

    '''Generate a hash id'''
    hashids = Hashids(salt=_HASH_SALT)
    _uuid = uuid.uuid1().int >> 64
    return hashids.encode(_uuid)

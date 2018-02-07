__author__ = 'mwvaughn'

import json
import os


HERE = os.path.dirname(os.path.abspath(__file__))


class TestData(object):

    def __init__(self, credentials):
        self.local_data = credentials
        self.dat = self.file_to_json('testdata.json')

    def file_to_json(self, filename):
        return json.load(open(os.path.join(HERE, filename)))

    def data(self, key=None):
        if key is None:
            return self.dat
        else:
            return self.dat.get(key, None)

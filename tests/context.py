# -*- coding: utf-8 -*-

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


class MockPortalAPI:
    def get_json(self, url):
        return {}

    def list_json(self, url):
        return {}

    def post_json(self, url, data):
        return {}

    def put_json(self, url, data):
        return {}

class MockVaultClient:
    data = {}

    def store_tls_cert(self, fqdn, cert, privatekey, ca):
        self.data[fqdn] = {
            "ca": ca,
            "private": privatekey,
            "cert": cert,
        }

    def get_v2_secret(self, partition, fqdn, key):
        return self.data[fqdn][key]

    def get_tls_cert(self, fqdn):
        return self.data[fqdn]

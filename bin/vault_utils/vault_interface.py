#    Copyright 2020 Splunk, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import requests
from .engine import VaultEngine

class Vault(object):

    def __init__(self, addr, token, namespace=None):
        self._addr = addr
        self._api_url = "{0}/v1".format(addr)
        self._token = token
        self._namespace = namespace

    @property
    def headers(self):
        headers = { "X-Vault-Token": self._token }
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace

        return headers

    def url_for_path(self, path):
        return "{0}/{1}".format(self._api_url, path)

    def engine(self, engine_type, engine_path):
        return VaultEngine.engine_at_path(self, engine_type, engine_path)

    def _get(self, path):
        url = self.url_for_path(path)
        print("GET {0}".format(url))
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()

        return response.json()["data"]

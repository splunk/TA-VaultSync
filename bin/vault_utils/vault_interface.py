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
import json
from .engine import VaultEngine

class Vault(object):

    def __init__(self, addr, approle_path, role_id, secret_id, namespace=None):
        self._addr = addr
        self._api_url = "{0}/v1".format(addr)
        self._approle_path = approle_path
        self._role_id = role_id
        self._secret_id = secret_id
        self._namespace = namespace
        self._token = self._authenticate_approle()

    # TODO - this should be abstracted into an authentication method class
    def _authenticate_approle(self):
        auth_data = json.dumps({
            "role_id": self._role_id,
            "secret_id": self._secret_id,
        })

        auth_url = self.url_for_path(
            "auth/{0}/login".format(self._approle_path)
        )

        r = requests.post(auth_url, data=auth_data)

        # TODO - this needs error handling
        return r.json()["auth"]["client_token"]

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

    def _get(self, path, params={}):
        url = self.url_for_path(path)
        print("GET {0}".format(url))
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()

        return response.json()["data"]

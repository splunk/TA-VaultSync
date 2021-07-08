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

import json

from .engine import ConfiguredEngine, VaultEngine
from .secret import VaultSecret

@ConfiguredEngine("kv")
class VaultKVEngine(VaultEngine):

    def secret(self, path):
        return VaultKVSecret(self, path)


class VaultKVSecret(VaultSecret):

    def __init__(self, vault_engine, path, version=None):
        super(VaultKVSecret, self).__init__(vault_engine, path)

        # explicit version defined
        self._version = version

        # attempt to use a requested "version 0"
        if self._version is None:
            # if explicitly defined version was, well, not defined, ask for and use the latest
            self._version = self.version()


    def _get(self):
        if self._version is not None:
            return super(VaultKVSecret, self)._get(params={'version': self._version})

        return super(VaultKVSecret, self)._get()

    def version(self):
        return self._get()["metadata"]["version"]

    def json(self):
        # Vault._get already returns a deserialized object from the returned JSON, so reserialize it when asked to
        return json.dumps(self._get()["data"])

    def key(self, key):
        return self._get()["data"][key]

    def previous_version_number(self):
        return self._version - 1

    def previous_version(self):
        if self.previous_version_number() == 0:
            return None

        previous_version = VaultKVSecret(self._vault_engine, self._path, self._version - 1)

        try:
            previous_version.version()
        except:
            return None

        return previous_version

    def previous_versions(self):
        my_previous_version = self.previous_version()

        while my_previous_version:
            yield my_previous_version
            my_previous_version = my_previous_version.previous_version()

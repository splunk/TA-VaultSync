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

class VaultSecret(object):

    def __init__(self, vault_engine, path):
        self._vault_engine = vault_engine
        self._path = path

    def _get(self):
        data_path = "data/{0}".format(self._path)

        return self._vault_engine._get(data_path)

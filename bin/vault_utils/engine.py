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

# VaultEngine is an abstract class and should not be used directly
# it should make use of ABCMeta to ensure it is not attempted
class VaultEngine(object):
    _engine_classes = { }

    def __init__(self, vault, engine_path):
        self._vault = vault
        self._engine_path = engine_path

    @classmethod
    def _add_engine_class(cls, engine_type, engine_class):
        cls._engine_classes[engine_type] = engine_class

    @classmethod
    def _engine_class_for_type(cls, engine_type):
        if not engine_type in cls._engine_classes:
            raise Exception('Unknown engine type: {0}'.format(engine_type))

        return cls._engine_classes[engine_type]

    @classmethod
    def engine_at_path(cls, vault, engine_type, engine_path):
        engine_class = cls._engine_class_for_type(engine_type)

        return engine_class(vault, engine_path)

    def _get(self, path, params={}):
        path_with_engine = "{0}/{1}".format(self._engine_path, path)

        return self._vault._get(path_with_engine, params=params)


# decorator that tells VaultEngine we exist
class ConfiguredEngine(object):
    def __init__(self, engine_type):
        self._engine_type = engine_type

    def __call__(self, configured_class):
        VaultEngine._add_engine_class(self._engine_type, configured_class)

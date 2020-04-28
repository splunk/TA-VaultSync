from engine import ConfiguredEngine, VaultEngine
from secret import VaultSecret

@ConfiguredEngine("kv")
class VaultKVEngine(VaultEngine):

    def secret(self, path):
        return VaultKVSecret(self, path)


class VaultKVSecret(VaultSecret):

    def key(self, key):
        return self._get()["data"][key]

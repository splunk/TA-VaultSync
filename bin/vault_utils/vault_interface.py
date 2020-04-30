import requests
from engine import VaultEngine

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

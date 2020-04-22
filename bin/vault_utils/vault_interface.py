import requests

class Vault(object):
    def __init__(self, addr, token, namespace=None):
        self._addr = addr
        self._token = token
        self._namespace = namespace

    def kv_secret(self, engine, path):
        secret_url = "{0}/v1/{1}/data/{2}".format(self._addr, engine, path)

        headers = { "X-Vault-Token": self._token }
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace

        response = requests.get(secret_url, headers=headers)

        response.raise_for_status()

        return response.json()["data"]

    def kv_secret_key(self, engine, path, key):
        return self.kv_secret(engine=engine, path=path)["data"][key]

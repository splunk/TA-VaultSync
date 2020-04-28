class VaultSecret(object):

    def __init__(self, vault_engine, path):
        self._vault_engine = vault_engine
        self._path = path

    def _get(self):
        data_path = "data/{0}".format(self._path)

        return self._vault_engine._get(data_path)

import logging

import splunklib.client as client


class DataEncryption(object):
    def __init__(self, session_key, input_name):
        self._session_key = session_key
        self._masked_password = '**********'
        self._input_name = input_name

    def encrypt_and_get_password(self, client_id, secret, ew, updated_item):
        try:
            # If the password is not masked, mask it.
            if secret != self._masked_password:
                self.encrypt_password(client_id, secret)
                self.mask_password(updated_item)

            return self.get_password(client_id)
        except Exception as e:
            ew.log("ERROR", "Encrypt Password Error: %s" % logging.exception(e))

    def encrypt_password(self, username, secret):
        args = {'token': self._session_key}
        service = client.connect(**args)

        try:
            # If the credential already exists, delete it.
            for storage_password in service.storage_passwords:
                if storage_password.username == username:
                    service.storage_passwords.delete(username=storage_password.username)
                    break

            # Create the credential.
            service.storage_passwords.create(secret, username)

        except Exception as e:
            raise Exception(
                "An error occurred updating credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities. Details: %s" % str(
                    e))

    def mask_password(self, kwargs):
        try:
            args = {'token': self._session_key}
            service = client.connect(**args)
            kind, name = self._input_name.split("://")
            item = service.inputs.__getitem__((name, kind))

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))

    def get_password(self, username):
        args = {'token': self._session_key}
        service = client.connect(**args)

        # Retrieve the password from the storage/passwords endpoint
        for storage_password in service.storage_passwords:
            if storage_password.username == username:
                return storage_password.content.clear_password

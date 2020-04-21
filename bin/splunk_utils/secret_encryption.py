import logging

import splunklib.client as client
from splunklib.binding import UrlEncoded


class SecretEncryption(object):
    _masked_secret = '**********'


    def __init__(self, input_stanza, service, realm_prefix=None, logger=None):
        self._service = service
        self._input_type, self._input_name = input_stanza.split('://')
        self._logger = logger

        # use specified realm_prefix, or the input type if none was given
        self._realm_prefix = realm_prefix
        if not self._realm_prefix:
            self._realm_prefix = self._input_type


    def encrypt_and_get_secret(self, secret, field):
        # If the secret is not masked, encrypt then mask it.
        if secret != self._masked_secret:
            self.encrypt_secret(secret, field)
            self.mask_secret(field)

        return self.get_secret(field)


    def _credential_realm_for_field(self, field):
        return "{0}-{1}".format(self._realm_prefix, field)

        
    def encrypt_secret(self, secret, field):
        # If the credential already exists, delete it.
        found_secret = self.credential_for_field(field)
        if found_secret:
            found_secret.delete()

        # Create the credential.
        self._service.storage_passwords.create(secret, self._input_name, self._credential_realm_for_field(field))


    def mask_secret(self, field):
        inputs_kind_path = self._service.inputs.kindpath(self._input_type)
        inputs_path_for_kind = "{0}/{1}".format("data/inputs", inputs_kind_path)
        input_path = "{0}/{1}".format(inputs_path_for_kind, UrlEncoded(self._input_name, encode_slash=True))
        input = self._service.input(input_path)

        # this causes the input config to refresh, resulting in this input instance ending and being started again
        input.update(**{field: self._masked_secret})


    def get_secret(self, field):
        found_credential = self.credential_for_field(field).content.clear_password
        if found_credential:
            return self.credential_for_field(field).content.clear_password

        raise Exception("No credential found for {0} in realm {1}".format(field, self._credential_realm_for_field(field)))


    def credential_for_field(self, field):
        for credential in self._service.storage_passwords:
            if credential.realm == self._credential_realm_for_field(field) and credential.username == self._input_name:
                return credential

        return None

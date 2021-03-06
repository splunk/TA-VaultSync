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

import logging

import splunklib.client as client
from splunklib.binding import UrlEncoded


class SecretEncryption(object):
    _masked_secret = '**********'


    def __init__(self, input_stanza, service, realm_prefix=None, required_on_edit_fields=[]):
        self._service = service
        self._input_type, self._input_name = input_stanza.split('://')
        self._required_on_edit_fields = required_on_edit_fields

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


    def _credential_realm(self):
        return "{0}-{1}".format(self._realm_prefix, self._input_name)

        
    def encrypt_secret(self, secret, field):
        # If the credential already exists, update it.
        found_secret = self.credential_for_field(field)
        if found_secret:
            found_secret.update(password=secret)

        else:
            # Create the credential.
            self._service.storage_passwords.create(secret, field, self._credential_realm())


    def mask_secret(self, field):
        inputs_kind_path = self._service.inputs.kindpath(self._input_type)
        inputs_path_for_kind = "{0}/{1}".format("data/inputs", inputs_kind_path)
        input_path = "{0}/{1}".format(inputs_path_for_kind, UrlEncoded(self._input_name, encode_slash=True))
        input = self._service.input(input_path)

        # the change we are explicitly making
        input_changes = {
            field: self._masked_secret,
        }

        # add fields that are required on edit
        for field_name in self._required_on_edit_fields:
            if not field_name in input_changes:
                input_changes[field_name] = input.content[field_name]

        # this causes the input config to refresh, resulting in this input instance ending and being started again
        input.update(**input_changes)


    def get_secret(self, field):
        found_credential = self.credential_for_field(field)
        if found_credential:
            return found_credential.content.clear_password

        raise Exception("No credential found for {0} in realm {1}".format(field, self._credential_realm()))


    def credential_for_field(self, field):
        password_name = "{0}:{1}:".format(self._credential_realm(), field)
        if password_name in self._service.storage_passwords:
            return self._service.storage_passwords[password_name]

        return None

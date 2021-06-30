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

from __future__ import absolute_import

from splunklib.modularinput import *
from splunklib import client
import sys
import os
import logging
import logging.handlers
from splunk_utils import secret_encryption
from vault_utils import vault_interface


class VaultSyncKVCredentialScript(Script):
    _script_name = "vault_sync_kv_credential"

    _arguments = {
        "vault_url": {
            "title": "Hashicorp Vault URL",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_namespace": {
            "title": "The namespace in vault containing your secret",
             "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "vault_approle_auth_path": {
            "title": "Path to the AppRole authentication method",
            "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "vault_approle_role_id": {
            "title": "AppRole role_id with read access to your secret",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_approle_secret_id": {
            "title": "AppRole secret_id for your role_id",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_engine_path": {
            "title": "The path to the KV Engine containing your secret",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_secret_path": {
            "title": "The path, relative from vault_engine_path, of your secret",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_username_key": {
            "title": "The key in your KV secret containing the username to synchronize",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_password_key": {
            "title": "The key in your KV secret containing the password to synchronize",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "credential_app": {
            "title": "The app context to use for the created/updated credential",
            "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "credential_realm": {
            "title": "The realm of the created/updated credential",
            "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "remove_old_versions": {
            "title": "How many old versions of this secret should be forcibly removed from passwords.conf",
            "data_type": Argument.data_type_number,
            "required_on_create": False,
        },
    }

    _encrypted_arguments = [ 'vault_approle_role_id', 'vault_approle_secret_id' ]


    def configure_logging(self):
        # get this script's configuration
        script_config = self.service.confs[self._script_name]

        # set logging specific variables from config
        logging_config = script_config["logging"]
        max_bytes = int(logging_config["rotate_max_bytes"])
        backup_count = int(logging_config["rotate_backup_count"])
        log_level = getattr(logging, logging_config["log_level"])

        # configure our logger
        self._logger = logging.getLogger(self._script_name)
        self._logger.setLevel(log_level)
        self._logger.propagate = False

        # configure our log handler
        log_dir = os.path.expandvars(os.path.join("$SPLUNK_HOME", "var", "log", "splunk"))
        log_file = os.path.join(log_dir, "{0}.log".format(self._script_name))
        log_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        log_formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')
        log_handler.setFormatter(log_formatter)

        # add our handler to our logger
        self._logger.addHandler(log_handler)


    def get_scheme(self):
        scheme = Scheme("Vault Synchronize KV Credential")
        scheme.use_single_instance = False

        for argument_name, argument_config in self._arguments.items():
            scheme_argument = Argument(argument_name, **argument_config)
            scheme.add_argument(scheme_argument)

        return scheme


    def stream_events(self, inputs, ew):
        # logging can't be configured until this point
        # there is no session key available during __init__ (or get_scheme), and we need it to get the running config
        self.configure_logging()

        self._logger.debug("stream_events")

        for input_name, input_config in inputs.inputs.items():
            self._logger.debug("input_name: {0}".format(input_name))

            for argument_name in self._arguments:
                if argument_name not in input_config:
                    if self._arguments[argument_name].get('required_on_create'):
                        self._logger.critical("{0} Missing required field {1}, quitting".format(input_name, argument_name))
                        sys.exit(-1)

                # use .get(argument_name) to use the default of None if missing
                setattr(self, argument_name, input_config.get(argument_name))
                self._logger.debug("{0}: fetched argument {1}".format(input_name, argument_name))

            required_on_edit_field_names = filter(lambda argument_name: self._arguments[argument_name].get("required_on_edit", False), self._arguments)
            encryption = secret_encryption.SecretEncryption(input_stanza=input_name, service=self.service, required_on_edit_fields=required_on_edit_field_names)

            for argument_name in self._encrypted_arguments: 
                # all encrypted arguments in this input are required, so the checking above should be sufficient
                setattr(self, argument_name, encryption.encrypt_and_get_secret(getattr(self, argument_name), argument_name))
                self._logger.debug("{0}: handled encrypted argument {1}".format(input_name, argument_name))

        try:
            vault = vault_interface.Vault(addr=self.vault_url, namespace=self.vault_namespace, approle_path=self.vault_approle_auth_path, role_id=self.vault_approle_role_id, secret_id=self.vault_approle_secret_id)
        except Exception as e:
            self._logger.critical("unable to authenticate to vault: {0}".format(e))
            exit(-1)

        vault_kv_engine = vault.engine("kv", self.vault_engine_path)

        try:
            vault_kv_secret = vault_kv_engine.secret(self.vault_secret_path)
        except Exception as e:
            self._logger.critical("unable to fetch secret: {0}".format(e))
            exit(-1)

        try:
            fetched_secret_version = vault_kv_secret.version()
        except Exception as e:
            self._logger.critical("unable to fetch secret: {0}".format(e))
            exit(-1)

        self._logger.debug("{0}: latest KV secret version: {1}".format(input_name, fetched_secret_version))

        try:
            fetched_vault_username = vault_kv_secret.key(self.vault_username_key)
            fetched_vault_password = vault_kv_secret.key(self.vault_password_key)
        except Exception as e:
            self._logger.critical("unable to fetch secret: {0}".format(e))
            exit(-1)

        credential_session = self.service
        # switch app context if one was specified
        if self.credential_app:
            credential_session = client.connect(app=self.credential_app, token=self.service.token)

        # default realm to empty string
        credential_title = "{0}:{1}:".format(self.credential_realm or "", fetched_vault_username)

        self._logger.debug("{0}: working with credential: {1}".format(input_name, credential_title))

        if credential_title in credential_session.storage_passwords:
            self._logger.debug("{0}: found existing credential".format(input_name))

            found_credential = credential_session.storage_passwords[credential_title]
            if found_credential.content.clear_password != fetched_vault_password:
                self._logger.debug("{0}: stored credential is out of date, updating".format(input_name))
                found_credential.update(password=fetched_vault_password)
            else:
                self._logger.debug("{0}: stored credential is up to date, doing nothing".format(input_name))

        else:
            self._logger.info("{0}: no existing credential found, creating".format(input_name))
            credential_session.storage_passwords.create(fetched_vault_password, fetched_vault_username, self.credential_realm)
            self._logger.debug("{0}: credential created".format(input_name))

        if self.remove_old_versions:
            # TODO - do type conversions when fetching arguments
            oldest_removeable_version = vault_kv_secret.version() - int(self.remove_old_versions)

            self._logger.info("{0}: removeable versions".format(input_name))
            for previous_version in vault_kv_secret.previous_versions():
                if previous_version.version() < oldest_removeable_version:
                    break
                self._logger.info("  {0}: previous version: {1}".format(input_name, previous_version.version()))

                previous_version_vault_username = previous_version.key(self.vault_username_key)

                # we only need to look for differing usernames, because differing passwords with the same username will have already been updated
                if previous_version_vault_username != fetched_vault_username:
                    self._logger.debug("  {0}: version {1} is stale".format(input_name, previous_version.version()))
                    credential_title = "{0}:{1}:".format(self.credential_realm or "", previous_version_vault_username)
                    if credential_title in credential_session.storage_passwords:
                        self._logger.info("  {0}: version {1}'s username has an old entry in passwords.conf, removing".format(input_name, previous_version.version()))
                        credential_session.storage_passwords[credential_title].delete()
                else:
                    self._logger.info("  {0}: version {1} is identical to latest".format(input_name, previous_version.version()))

if __name__ == "__main__":
    sys.exit(VaultSyncKVCredentialScript().run(sys.argv))

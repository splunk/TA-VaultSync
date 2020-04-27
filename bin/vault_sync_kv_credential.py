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
            "title": "Vault URL",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_namespace": {
            "title": "Vault Namespace",
             "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "vault_token": {
            "title": "Vault Token",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_engine_path": {
            "title": "Vault Engine Path",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_secret_path": {
            "title": "Vault Secret Path",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_secret_key": {
            "title": "Vault Secret Key",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "credential_app": {
            "title": "Credential App Context",
            "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "credential_realm": {
            "title": "Credential Realm",
            "data_type": Argument.data_type_string,
            "required_on_create": False,
        },
        "credential_username": {
            "title": "Credential Username",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
    }

    _encrypted_arguments = [ 'vault_token' ]


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
                        exit(-1)

                # use .get(argument_name) to use the default of None if missing
                setattr(self, argument_name, input_config.get(argument_name))
                self._logger.debug("{0}: fetched argument {1}".format(input_name, argument_name))

            required_on_edit_field_names = filter(lambda argument_name: self._arguments[argument_name].get("required_on_edit", False), self._arguments)
            encryption = secret_encryption.SecretEncryption(input_stanza=input_name, service=self._service, required_on_edit_fields=required_on_edit_field_names)

            for argument_name in self._encrypted_arguments: 
                # all encrypted arguments in this input are required, so the checking above should be sufficient
                setattr(self, argument_name, encryption.encrypt_and_get_secret(getattr(self, argument_name), argument_name))
                self._logger.debug("{0}: handled encrypted argument {1}".format(input_name, argument_name))

        vault = vault_interface.Vault(addr=self.vault_url, namespace=self.vault_namespace, token=self.vault_token)

        fetched_vault_secret = vault.kv_secret_key(engine=self.vault_engine_path, path=self.vault_secret_path, key=self.vault_secret_key)

        credential_session = self._service
        # switch app context if one was specified
        if self.credential_app:
            credential_session = client.connect(app=self.credential_app, token=self._service.token)

        # default to empty realm
        credential_title = ":{0}:".format(self.credential_username)
        if self.credential_realm:
            # use realm is given
            credential_title = "{0}:{1}:".format(self.credential_realm, self.credential_username)

        self._logger.debug("{0}: working with credential: {1}".format(input_name, credential_title))

        if credential_title in credential_session.storage_passwords:
            self._logger.debug("{0}: found existing credential".format(input_name))

            found_credential = credential_session.storage_passwords[credential_title]
            if found_credential.content.clear_password != fetched_vault_secret:
                self._logger.debug("{0}: stored credential is out of date, updating".format(input_name))
                found_credential.update(password=fetched_vault_secret)
            else:
                self._logger.debug("{0}: stored credential is up to date, doing nothing".format(input_name))

        else:
            self._logger.info("{0}: no existing credential found, creating".format(input_name))
            credential_session.storage_passwords.create(fetched_vault_secret, self.credential_username, self.credential_realm)
            self._logger.debug("{0}: credential created".format(input_name))

if __name__ == "__main__":
    sys.exit(VaultSyncKVCredentialScript().run(sys.argv))

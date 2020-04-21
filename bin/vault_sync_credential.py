from __future__ import absolute_import

from splunklib.modularinput import *
import sys
import os
import logging
import logging.handlers
from splunk_utils import secret_encryption


class VaultSyncCredentialScript(Script):
    _script_name = "vault_sync_credential"

    _arguments = {
        "vault_url": {
            "title": "Vault URL",
            "data_type": Argument.data_type_string,
            "required_on_create": True,
        },
        "vault_token": {
            "title": "Vault Token",
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
            "required_on_create": True,
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
        scheme = Scheme("Vault Synchronize Credential")
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
                setattr(self, argument_name, input_config[argument_name])
                self._logger.debug("{0}: fetched argument {1}".format(input_name, argument_name))

            encryption = secret_encryption.SecretEncryption(input_stanza=input_name, service=self._service)
            for argument_name in self._encrypted_arguments: 
                setattr(self, argument_name, encryption.encrypt_and_get_secret(getattr(self, argument_name), argument_name))
                self._logger.debug("{0}: handled encrypted argument {1}".format(input_name, argument_name))


if __name__ == "__main__":
    sys.exit(VaultSyncCredentialScript().run(sys.argv))

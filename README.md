# Hashicorp Vault Synchronization

Synchronize secrets from Hashicorp Vault to Splunk's Credential Store.

## Configuration

### inputs.conf

#### [vault_sync_kv_credential] - Vault Synchronize KV Credential

Synchronize secrets from Hashicorp Vault's KV Engine to Splunk's Credential Store.

    [vault_sync_kv_credential://<name>]
    * Create an input per-credential you wish to synchronize
    * Use a meaningful value for <name> to differentiate your configured inputs

    interval = <integer>
    * How often, in seconds, to check Hashicorp Vault for an updated secret
    * Required

    vault_url = <string>
    * Hashicorp Vault URL
    * Required

    vault_namespace = <string>
    * The namespace in vault containing your secret
    * Optional

    vault_approle_auth_path = <string>
    * Path at which your AppRole authentication method is enabled, with no leading or trailing slash
    * https://www.vaultproject.io/api-docs/system/auth#path
    * Defaults to "approle"

    vault_approle_role_id = <string>
    * The role_id of an AppRole that has read access to your secret
    * This will be encrypted into Splunk's Credential Store any time the input runs and detects a plaintext value
    * Required

    vault_approle_secret_id = <string>
    * A secret_id granting access to your role_id
    * This will be encrypted into Splunk's Credential Store any time the input runs and detects a plaintext value
    * Vault allows using only a role_id, without a secret_id along with it, but this Add-on requires a secret_id
    * Required

    vault_engine_path = <string>
    * The path to the KV Engine containing your secret
    * Required

    vault_secret_path = <string>
    * The path, relative from vault_engine_path, of your secret
    * Required

    vault_username_key = <string>
    * The key in your KV secret containing the username to synchronize
    * Required

    vault_secret_key = <string>
    * The key in your KV secret containg the username to synchronize
    * Required

    remove_old_versions = <integer>
    * How many old versions of your KV secret should be removed from your passwords.conf
    * Needed for Add-ons like the AWS TA, which programmatically fetches the username from a credential defined in a specific realm
    * Defaults to 0

    credential_app = <string>
    * The app context to use for the created/updated credential
    * Optional

    credential_realm = <string>
    * The realm of the created/updated credential
    * Optional

 ### vault_sync_kv_credential.conf

 #### [logging] - Configure logging for the input

    [logging]
    rotate_max_bytes = <integer>
    * Rotate log files after rotate_max_bytes bytes.
    * Default is 1000000

    rotate_backup_count = <integer>
    * Keep rotate_backup_count rotated (inactive) log files
    * Default is 5

    log_level = [CRITICAL|ERROR|WARNING|INFO|DEBUG|NOTSET]
    * Set the log level.  Valid values are shown above.
    * Default is INFO

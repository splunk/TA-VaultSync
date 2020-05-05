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
    * Vault URL
    * Your Hashicorp Vault URL
    * Required
    
    vault_namespace = <string>
    * Vault Namespace
    * The namespace your secret resides in
    * Optional
    
    vault_token = <string>
    * Vault Token
    * An authorization token with read access to your secret
    * This will be encrypted into Splunk's Credential Store any time the input runs and detects a plaintext value
    * Required
    
    vault_engine_path = <string>
    * Vault Engine Path
    * The path to the KV Engine your secret is stored in
    * Required

    vault_secret_path = <string>
    * Vault Secret Path
    * The path, underneath vault_engine_path, that points to your secret
    * Required
    
    vault_secret_key = <string>
    * Vault Secret Key
    * The key of your KV secret that contains the value you want to synchronize into Splunk's Credential Store
    * Required
    
    credential_app = <string>
    * Credential App Context
    * The app context to use for the created/updated credential
    * Optional
    
    credential_realm = <string>
    * Credential Realm
    * The realm of the created/updated credential
    * Optional
    
    credential_username = <string>
    * Credential Username
    * The username of the created/updated credential
    * Required
    
 ### vault_sync_kv_credential.conf
 
 #### [logging] - Configure logging for the input
 
    [logging]
    rotate_max_bytes = <integer>
    * Rotate log files after rotate_max_bytes bytes.
    * Default is 1000000

    rotate_backup_count = <integer>
    * Keep rotate_backup_count rotated (inactive) log files

    log_level = [CRITICAL|ERROR|WARNING|INFO|DEBUG|NOTSET]
    * Set the log level.  Valid values are:
    * CRITICAL
    * ERROR
    * WARNING
    * INFO
    * DEBUG
    * NOTSET

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
    
    vault_token = <string>
    * Authorization token with read access to your secret
    * This will be encrypted into Splunk's Credential Store any time the input runs and detects a plaintext value
    * Required
    
    vault_engine_path = <string>
    * The path to the KV Engine containing your secret
    * Required

    vault_secret_path = <string>
    * The path, relative from vault_engine_path, of your secret
    * Required
    
    vault_secret_key = <string>
    * The key in your KV secret to synchronize
    * Required
    
    credential_app = <string>
    * The app context to use for the created/updated credential
    * Optional
    
    credential_realm = <string>
    * The realm of the created/updated credential
    * Optional
    
    credential_username = <string>
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
    * Set the log level.  Valid values are shown above.
    * Defaults to INFO

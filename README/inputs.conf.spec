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

[vault_sync_kv_credential://<name>]
python.version = python3
vault_url = <string>
vault_namespace = <string>
vault_approle_auth_path = <string>
vault_approle_role_id = <string>
vault_approle_secret_id = <string>
vault_engine_path = <string>
vault_secret_path = <string>
vault_username_key = <string>
vault_password_key = <string>
credential_store_json = <bool>
credential_app = <string>
credential_realm = <string>
remove_old_versions = <integer>

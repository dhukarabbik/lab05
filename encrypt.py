from azure.keyvault.keys import KeyClient
from azure.identity import DefaultAzureCredential
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Azure Key Vault details
KEY_VAULT_URL = "https://mykeyvaultsecops.vault.azure.net/"
KEY_ID = " https://mykeyvaultsecops.vault.azure.net/keys/myencryptionkey/60c537611a61452292577ee60cc7970d"

# Authenticate with Azure
credential = DefaultAzureCredential()

# Create a Key Client
key_client = KeyClient(vault_url=KEY_VAULT_URL, credential=credential)

# Generate a new encryption key
key_name = "myencryptionkey"
rsa_key = key_client.create_rsa_key(name=key_name, size=2048)
print(f"Key ID: {rsa_key.id}")
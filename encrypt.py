from azure.keyvault.keys import KeyClient
from azure.identity import DefaultAzureCredential
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging
logging.basicConfig(level=logging.DEBUG)

# Azure Key Vault details
KEY_VAULT_URL = "https://mykeyvaultsecops.vault.azure.net/"
KEY_ID = "myencryptionkey/60c537611a61452292577ee60cc7970d"

# Authenticate with Azure
credential = DefaultAzureCredential()

# Create a Key Client
key_client = KeyClient(vault_url=KEY_VAULT_URL, credential=credential)

# Get the encryption key
key = key_client.get_key(KEY_ID)

# Encrypt the user input
user_input = input("Enter a string to encrypt: ")
plaintext = user_input.encode()

# Encrypt the data
encrypted = key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Encrypted data: {encrypted.hex()}")
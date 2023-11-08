from ecdsa import SigningKey, SECP256k1
from bit import Key
from bsvlib import Wallet, Key as BSVKey, Unspent, Transaction, TxOutput, TxInput, verify_signed_text
from bsvlib.constants import Chain, SIGHASH
from bsvlib.script import P2pkScriptType, BareMultisigScriptType, Script
# from bsvlib.service import WhatsOnChain
import os
import hashlib
import binascii
import time
import requests
import json
import uuid

# Path to the file where the private key will be stored
KEY_FILE_PATH = "private_key.txt"
UUID_FILE_PATH = "device_uuid.txt"

# Function to generate a SHA256 hash of a string
def hash_string(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

# Function to post data to an API
def post_data_to_api(url, data):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, data=json.dumps(data), headers=headers)
    return response.json()

# Function to generate new private and public key pairs
def generate_key_pair():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    private_key_hex = sk.to_string().hex()
    public_key_hex = vk.to_string().hex()

    # Convert private key into WIF format using bit library
    private_key = Key.from_hex(private_key_hex)
    private_key_wif = private_key.to_wif()

    return private_key_wif, public_key_hex, private_key.address

def get_balance(wallet):
    # Setting WhatsOnChain as the provider
    wallet.provider = WhatsOnChain(Chain.MAIN)  # or Chain.TEST for testnet

    # Get balance
    balance = wallet.get_balance(refresh=True)

    return balance

# Function to store the private key in a file
def store_key_in_file(key):
    with open(KEY_FILE_PATH, "w") as file:
        file.write(key)

# Function to retrieve the private key from a file
def get_key_from_file():
    if os.path.exists(KEY_FILE_PATH):
        with open(KEY_FILE_PATH, "r") as file:
            return file.read().strip()
    return None

def store_uuid_in_file(uuid):
    with open(UUID_FILE_PATH, "w") as file:
        file.write(str(uuid))

def get_uuid_from_file():
    if os.path.exists(UUID_FILE_PATH):
        with open(UUID_FILE_PATH, "r") as file:
            return uuid.UUID(file.read().strip())
    return None


def call_funding_api(url, address, uuid):
    data = {'address': address, 'uuid': str(uuid)}
    response = post_data_to_api(url, data)

    if response.get('success'):
        print("Successfully funded new TEMPEST Device address.")
        print("Transaction ID: ", response.get('data'))
        print("Device Balance: ", response.get('amount'))
        print("Device Address: ", response.get('address'))
    else:
        print("Funding failed.")

    return response


# Replace [your_station_id] and [your_access_token] with your actual values
def get_weather_data(station_id, access_token):
    url = f"https://swd.weatherflow.com/swd/rest/observations/station/{station_id}?token={access_token}"

    # Send a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Extract the JSON data from the response
        data = response.json()

        # Convert the JSON data to a string
        json_string = json.dumps(data)

        return json_string
    else:
        print("Failed to retrieve data.")
        return None

# Replace [your_station_id] and [your_access_token] with your actual values
station_id = "23971"
access_token = "67de1821-df42-457b-b4df-5712385556f2"

# Call the function to get the weather data
# weather_data = get_weather_data(station_id, access_token)

# Check if the weather data was retrieved successfully
# if weather_data:
#     print(weather_data)

# Main function
if __name__ == "__main__":
    while True:
        stored_key = get_key_from_file()
        device_uuid = get_uuid_from_file()

        if device_uuid is None:
            device_uuid = uuid.uuid4()
            store_uuid_in_file(device_uuid)

        if stored_key is None:
            private_key, public_key, address = generate_key_pair()
            store_key_in_file(private_key)

            # Call the funding API for the first time
            funding_api_url = "https://agritech.live/api/v1/tempest/funding"
            funding_response = call_funding_api(funding_api_url, address, device_uuid)
            print("Funding API response: ", funding_response)

            # Wait for the funding transaction to confirm
            time.sleep(30)
        else:
            private_key = stored_key
            key_obj = Key(private_key)
            public_key = key_obj.public_key
            address = key_obj.address

        print(f"Device Private Key (WIF): {private_key}")
        print(f"Device Public Key: {public_key}")
        print(f"Device Address: {address}")

        # BSV related code follows

        # Instantiate a new Wallet and add the private key
        my_wallet = Wallet()
        my_wallet.add_key(private_key)

        # Access the key object
        my_key = my_wallet.keys[0]  # If only one key was added
        weather_data = get_weather_data(station_id, access_token) #
        hash = hash_string(weather_data)
        print(weather_data)
        # Encrypt and decrypt a message with the key pair
        plain = weather_data + time.ctime()
        encrypted = my_key.public_key().encrypt_text(plain)
        # print("Tempest Encrypted message: ", encrypted)
        # print("Tempest Decrypted message: ", my_key.decrypt_text(encrypted))

        # Sign a message with the private key
        address, signature = my_key.sign_text(weather_data)
        # print("Tempest Signed message: ", signature)
        # print("Verification: ", verify_signed_text(weather_data, address, signature))
        # print('Balance: ', get_balance(my_wallet))

        # Post data to API
        api_url = "https://agritech.live/api/v1/tempest"
        api_url2 = "https://agritech.live/api/v2/tempest"
        data = {
            # 'encrypted': encrypted,
            # 'plain': plain,
            'hash':hash,
            # 'signed_hex': signature,
            'address': address
        }
        response = post_data_to_api(api_url2, data)
        txid = response.get("txid")
        print("Agritech Live Blockchain Publish API response: ", response)
        print("TXID",txid)
        time.sleep(10)  # Wait for 10 seconds

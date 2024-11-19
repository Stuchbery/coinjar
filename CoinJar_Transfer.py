
import requests
import json
import time
import base64
import jwt
from cryptography.hazmat.primitives import serialization
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Add padding to the base64 string if necessary
def add_base64_padding(b64_str):
    padding = len(b64_str) % 4
    if padding != 0:
        b64_str += '=' * (4 - padding)
    return b64_str

# Function to sign the JWT
def sign_jwt(scope='trade', kid='f052ea09-f049-4023-aadf-32979ca0beb0'):
    # Load the private key from the JSON file
    with open('private_key.json', 'r') as file:
        private_key_json = json.load(file)

    # Import the private key (as base64 encoded string)
    private_key = private_key_json["d"]

    # Add padding to the base64 string and decode it to bytes
    private_key = add_base64_padding(private_key)
    private_key_bytes = base64.urlsafe_b64decode(private_key)

    # Load the EC private key from bytes using cryptography library
    private_key_obj = ec.derive_private_key(int.from_bytes(private_key_bytes, byteorder='big'), ec.SECP256R1(), default_backend())

    # PEM encode the private key
    pem_private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Define the payload
    payload = {
        "aud": "CJX",
        "scope": scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }

    # Define the header
    header = {
        "alg": "ES256",
        "kid": kid,
        "typ": "JWT"
    }

    # Sign the JWT using the private key (pem format)
    token = jwt.encode(payload, pem_private_key, algorithm='ES256', headers=header)

    return token


def user_info():

    base_url = 'https://api.exchange.coinjar.com'

    # Sign the JWT for 'trade' scope
    signature = sign_jwt(scope='trade', kid='f052ea09-f049-4023-aadf-32979ca0beb0')


    # Make the POST request to create the order
    response = requests.get(f'{base_url}/users/current',
                             headers={'Content-Type': 'application/json',
                                      'Authorization': f'Bearer {signature}'})

    # Return the response in JSON format
    return response.json()

# Function to create an order
def create_order():
    # base_url = 'https://api.exchange.coinjar-sandbox.com'
    base_url = 'https://api.exchange.coinjar.com'

    # Sign the JWT for 'trade' scope
    #signature = sign_jwt(scope='trade', kid='f052ea09-f049-4023-aadf-32979ca0beb0')
    signature = sign_jwt(scope='trades', kid='ba8a9e3f-8b72-418e-8f32-2155512603c3')

    # Create the order payload
    #"price": "100000",
    order_data = {
        "type": "MKT",
        "side": "buy",
        "size": "10",
        "product_id": "USDC-AUD"
    }

    # Make the POST request to create the order
    response = requests.post(f'{base_url}/orders',
                             headers={'Content-Type': 'application/json',
                                      'Authorization': f'Bearer {signature}'},
                             json=order_data)

    # Return the response in JSON format
    return response.json()

def get_scope():
    base_url = 'https://api.exchange.coinjar.com'

    # Sign the JWT for 'trade' scope
    #signature = sign_jwt(scope='read', kid='b18da364-bd1e-4bb0-ba11-e6c1a4e0ebb7')
    signature = sign_jwt(scope='trades', kid='ba8a9e3f-8b72-418e-8f32-2155512603c3')


    # Make the POST request to create the order
    response = requests.get(f'{base_url}/tokens/scope',
                             headers={'Content-Type': 'application/json',
                                      'Authorization': f'Bearer {signature}'})

    # Return the response in JSON format
    return response.json()

# Example usage
#53e78c71-34a2-4180-8ddf-dd921365557f

resp = get_scope()
print(resp)

order_response = create_order()
print(order_response)


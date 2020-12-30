import requests
import logging
import binascii
import json
import base64
import os
import subprocess
import time
import sys
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding



logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

DERIVED_KEY = None
CIPHER = None
MODE = None
DIGEST = None
PARAMETERS = None
PRIVATE_KEY = None
TOKEN = None

def send(method, endpoint, message=None):
    """
    Function used to send a make a request to a specific endpoint of the api of the server via HTTP protocol, adding the authentication
    token to the header if it exists

    @param: method Request method
    @param: endpoint Endopoint to which the request should be made
    @param: message Body of the message, default is None
    @return The request to the server's api
    """

    global TOKEN

    if TOKEN:
        header = {"Authorization": f"{TOKEN.strip()}"}
        if message is None and method == 'GET':
            return requests.get(url= f'{SERVER_URL}/{endpoint}', headers=header)  

        if method == 'GET':
            return requests.get(url= f'{SERVER_URL}/{endpoint}', params=message, headers=header)  
        
        if method == 'POST':
            return requests.post(url= f'{SERVER_URL}/{endpoint}', data= message, headers=header)  

    if message is None and method == 'GET':
        return requests.get(url= f'{SERVER_URL}/{endpoint}')  

    if method == 'GET':
        return requests.get(url= f'{SERVER_URL}/{endpoint}', params= message)  
    
    if method == 'POST':
        return requests.post(url= f'{SERVER_URL}/{endpoint}', data= message)  

def receive(requests):
    """
    Function used to receive an encrypted message from the server

    @param: request The request made to the server
    @return The message received in response to the request
    """

    message = requests.json()

    # if its a secure message we should authenticate it via the mac
    if message.get('type') == 'MAC_MSG':
        data = message.get('data').encode('latin')
        if authenticate_mac( binascii.a2b_base64(message.get('mac') ), data):
            message = data
        else:
            print(f'MAC authentication failed -- message compromised')
        message = json.loads(message)

    if message.get('type') == 'SECURE_MSG':
        data = base64.b64decode(message.get('data'))
        iv = base64.b64decode(message.get('iv'))

        message = decrypt(data, iv)
        message = json.loads(message)

    if message.get('type') == 'ERROR':
        print(message)
    
    return message


def authenticate_mac(mac, message):
    """
    Function used to verify if the mac is authentic based on the digest of a key 
    by a algorithm chosen in the negotiation between the server and the client

    @param: mac MAC received in a message from the server
    @param: message Message received
    @return True if the MAC is authenticated, False otherwise
    """

    global CIPHER

    # Slice key based on algorithm
    if CIPHER == "ChaCha20":
        key = DERIVED_KEY[:32]
    elif CIPHER == "AES":
        key = DERIVED_KEY[:16]
    elif CIPHER == "3DES":
        key = DERIVED_KEY[:8]

    # select the hash algoritm defined in the negotiations
    if DIGEST == 'SHA-256':
        algorithm = hashes.SHA256()
    elif DIGEST == 'SHA-384':
        algorithm = hashes.SHA384()
    elif DIGEST == 'SHA-512':
        algorithm = hashes.SHA512()

    _digest = hmac.HMAC(key, algorithm, backend=default_backend())
    _digest.update(message)

    try:
        _digest.verify(mac)
        return True
    except:
        return False

def decrypt(cryptogram, iv):
    """
    Function used to decrypt a criptogram using an iv and the mode and cipher negotiated
    between the client and the server. It also removes the necessary padding if the cipher 
    is made by blocks

    @param: cryptogram Cryptogram received from the server, containing the encrypted message
    @param: iv Initial Value used by the server to encrypt the message
    @return The text decrypted from the cryptogram received using the iv
    """

    if MODE == 'CBC':
        _mode = modes.CBC(iv)
    elif MODE == 'GCM':
        _mode = modes.GCM(iv)
    elif MODE == 'ECB':
        _mode = modes.ECB() 

    if CIPHER == "ChaCha20":
        key = DERIVED_KEY[:32]
        algorithm = algorithms.ChaCha20(key, iv)
        _cipher = Cipher(algorithm, mode=None, backend=default_backend())
    elif CIPHER == "AES":
        key = DERIVED_KEY[:16]
        algorithm = algorithms.AES(key)
        _cipher = Cipher(algorithm, _mode, backend=default_backend())
    elif CIPHER == "3DES":
        key = DERIVED_KEY[:8]
        algorithm = algorithms.TripleDES(key)
        _cipher = Cipher(algorithm, _mode, backend=default_backend())

    decryptor = _cipher.decryptor()
    text = decryptor.update(cryptogram) + decryptor.finalize()

    if CIPHER == 'ChaCha20':
        return text

    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    text = unpadder.update(text) + unpadder.finalize()

    return text

def get_dh_keys():
    """
    Function that triggeres the Diffie-Hellman's key generation process that generates the p and g 
    parameters, generates a private key and a shared secret, as well as deriving the latter in order 
    to create ephemeral keys for each session.
    This process is then repeated when the servers send a message with the type REGEN_KEY, to assure
    key rotation and therefore a extra level of security.  

    """

    global DERIVED_KEY
    global PARAMETERS
    global PRIVATE_KEY

    if not PARAMETERS:
        PARAMETERS = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())  
        parameter_numbers = PARAMETERS.parameter_numbers()
        message = {
            'type': 'DH_INIT',
            'p': parameter_numbers.p, 
            'g': parameter_numbers.g
        }
        req = send('POST', 'api/key', message)
        response = receive(req)

    if not PRIVATE_KEY:
        # generate a secret key
        PRIVATE_KEY = PARAMETERS.generate_private_key()

        # generate the public key based on the private one -> g^(private_key) mod p 
        public_key = PRIVATE_KEY.public_key()
        message = {
            'type': 'KEY_EXCHANGE',
            'public_key': public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode() 
        }
        req = send('POST', 'api/key', message)

        server_public_key = load_pem_public_key(response.get('public_key').encode(), backend=default_backend())
        shared_secret = PRIVATE_KEY.exchange(server_public_key)

        if DIGEST == 'SHA-256':
            algorithm = hashes.SHA256()
        elif DIGEST == 'SHA-384':
            algorithm = hashes.SHA384()
        elif DIGEST == 'SHA-512':
            algorithm = hashes.SHA512()

        # Derive key
        DERIVED_KEY = HKDF(
            algorithm = algorithm,
            length = algorithm.digest_size,
            salt = None,
            info = b'handshake',
            backend = default_backend()
        ).derive(shared_secret)

def login(username, password):
    """
    Function used to generate and send to the server the hash of the password as well as the username to receive
    an authentication token that should be used in the header of the requests made to the server.

    @param: username The client's username, that should be sent to the server
    @param: password The client's password, that should be hashed and sent to the server
    @return The authentication token generated by the server
    """

    if DIGEST == 'SHA-256':
        algorithm = hashes.SHA256()
    elif DIGEST == 'SHA-384':
        algorithm = hashes.SHA384()
    elif DIGEST == 'SHA-512':
        algorithm = hashes.SHA512()

    # Hash password
    h = hashes.Hash(algorithm, backend=default_backend())
    h.update(password.strip().encode('latin'))
    hashed_password = h.finalize()

    message = {
        'type': 'AUTH',
        'username': username,
        'data': hashed_password
    }
    req = send('POST', 'api/auth', message)
    response = receive(req)

    return (response.get('data'))
        
def main():

    global CIPHER
    global MODE
    global DIGEST
    global PARAMETERS
    global PRIVATE_KEY
    global TOKEN
    global username, password

    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    print("Contacting Server")

    # Secur the session
    if not CIPHER or not MODE or not DIGEST:
        message = {
            'type': 'NEGOTIATE',
            'mode': ["CBC", "GCM", "ECB"], 
            'cipher': ["ChaCha20", "AES", "3DES"], 
            'digest': ["SHA-256", "SHA-384", "SHA-512"]
        }
        req = send('POST', 'api/protocols', message)
        response = receive(req)
        CIPHER = response.get('cipher')
        MODE = response.get('mode')
        DIGEST = response.get('digest')

    get_dh_keys()

    if not TOKEN:

        # user inputs for login
        while True:
            username = input("Username: ")
            if len(username.strip()) != 0:
               break

        while True:
            password = getpass.getpass("Password: ")
            if len(password.strip()) != 0:
                break

        # Generate session token
        TOKEN = login(username, password)


    # Get a list of media files
    req = requests.get(f'{SERVER_URL}/api/list')
    req = send("GET", "api/list")
    if req.status_code == '200':
        print("Got Server List")

    media_list = receive(req).get('data')

    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = send('GET', f'api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = receive(req)
       
        # Regen key, if necessaty
        if chunk.get('type') == 'REGEN_KEY':
            PARAMETERS = None
            PRIVATE_KEY = None
            get_dh_keys()
            last_chunk =  chunk['last_chunk']

            TOKEN = login(username, password)

            req = send('GET', f'api/download?id={media_item["id"]}&chunk={last_chunk}')
            chunk = receive(req)

        # Process chunk
        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break
        chunk = 1

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)

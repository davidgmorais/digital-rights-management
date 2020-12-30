import requests
import logging
import binascii
import json
import base64
import os
import subprocess
import time
import sys
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

derived_key = None
cipher = None
mode = None
digest = None
parameters = None
private_key = None

def send(method, endpoint, message=None):
    if message is None and method == 'GET':
        return requests.get(url= f'{SERVER_URL}/{endpoint}')  

    if method == 'GET':
        return requests.get(url= f'{SERVER_URL}/{endpoint}', params= message)  
    
    if method == 'POST':
        return requests.post(url= f'{SERVER_URL}/{endpoint}', data= message)  

def receive(requests):
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

    return message


def authenticate_mac(mac, message):
    #mac = binascii.a2b_base64(mac)

    global cipher
    global digest

    # Slice key based on algorithm
    if cipher == "ChaCha20":
        key = derived_key[:32]
    elif cipher == "AES":
        key = derived_key[:16]
    elif cipher == "3DES":
        key = derived_key[:8]

    # select the hash algoritm defined in the negotiations
    if digest == 'SHA-256':
        algorithm = hashes.SHA256()
    elif digest == 'SHA-384':
        algorithm = hashes.SHA384()
    elif digest == 'SHA-512':
        algorithm = hashes.SHA512()

    _digest = hmac.HMAC(key, algorithm, backend=default_backend())
    _digest.update(message)

    try:
        _digest.verify(mac)
        return True
    except:
        return False

def decrypt(cryptogram, iv):

    global mode
    global cipher

    if mode == 'CBC':
        mode = modes.CBC(iv)
    elif mode == 'GCM':
        mode = modes.GCM(iv)
    elif mode == 'ECB':
        mode = modes.ECB() 

    if cipher == "ChaCha20":
        key = derived_key[:32]
        algorithm = algorithms.ChaCha20(key, iv)
        _cipher = Cipher(algorithm, mode=None, backend=default_backend())
    elif cipher == "AES":
        key = derived_key[:16]
        algorithm = algorithms.AES(key)
        _cipher = Cipher(algorithm, mode, backend=default_backend())
    elif cipher == "3DES":
        key = derived_key[:8]
        algorithm = algorithms.TripleDES(key)
        _cipher = Cipher(algorithm, mode, backend=default_backend())

    decryptor = _cipher.decryptor()
    text = decryptor.update(cryptogram) + decryptor.finalize()

    if cipher == 'ChaCha20':
        return text

    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    text = unpadder.update(text) + unpadder.finalize()

    return text

def get_dh_keys():

    global derived_key
    global cipher
    global mode
    global digest
    global parameters
    global private_key

    print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PARKOUR")

    if not parameters:
        parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())  
        parameter_numbers = parameters.parameter_numbers()
        message = {
            'type': 'DH_INIT',
            'p': parameter_numbers.p, 
            'g': parameter_numbers.g
        }
        req = send('POST', 'api/key', message)
        response = receive(req)

    if not private_key:
        # generate a secret key
        private_key = parameters.generate_private_key()

        # generate the public key based on the private one -> g^(private_key) mod p 
        public_key = private_key.public_key()
        message = {
            'type': 'KEY_EXCHANGE',
            'public_key': public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode() 
        }
        req = send('POST', 'api/key', message)

        server_public_key = load_pem_public_key(response.get('public_key').encode(), backend=default_backend())
        shared_secret = private_key.exchange(server_public_key)

        print(f'Got shared secret: {shared_secret}')

        if digest == 'SHA-256':
            algorithm = hashes.SHA256()
        elif digest == 'SHA-384':
            algorithm = hashes.SHA384()
        elif digest == 'SHA-512':
            algorithm = hashes.SHA512()

        # Derive key
        derived_key = HKDF(
            algorithm = algorithm,
            length = algorithm.digest_size,
            salt = None,
            info = b'handshake',
            backend = default_backend()
        ).derive(shared_secret)

        print(f'Got derived_key: {derived_key} with length {len(derived_key)}')

def main():

    global derived_key
    global cipher
    global mode
    global digest
    global parameters
    global private_key

    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    # TODO: Secure the session
    # req = requests.get(f'{SERVER_URL}/api/protocols')
    # if req.status_code == 200:
    #    prots = receive(req)

    message = {
        'type': 'NEGOTIATE',
        'mode': ["CBC", "GCM", "ECB"], 
        'cipher': ["ChaCha20", "AES", "3DES"], 
        'digest': ["SHA-256", "SHA-384", "SHA-512"]
    }
    req = send('POST', 'api/protocols', message)
    response = receive(req)
    cipher = response.get('cipher')
    mode = response.get('mode')
    digest = response.get('digest')

    get_dh_keys()



    ##############################################################################################




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
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = receive(req)
       
        # TODO: Process chunk
        if chunk.get('type') == 'REGEN_KEY':
            parameters = None
            private_key = None
            get_dh_keys()
            last_chunk =  chunk['last_chunk']
            req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={last_chunk}')
            chunk = receive(req)

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
import requests
import logging
import binascii
import json
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


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'



def main():
    derived_key = None
    cipher = None

    def send(method, endpoint, message):
        if derived_key and cipher:
            print("secure connection");

        if method == 'GET':
            return requests.get(url= f'{SERVER_URL}/{endpoint}', params= message)  
        elif method == 'POST':
            return requests.post(url= f'{SERVER_URL}/{endpoint}', data= message)  


    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    parameters = None
    private_key = None

    # TODO: Secure the session
    req = requests.get(f'{SERVER_URL}/api/protocols')
    if req.status_code == 200:
        prots = req.json()

    message = {
        'type': 'NEGOTIATE',
        'mode': ["CBC", "GCM", "ECB"], 
        'cipher': ["ChaCha20", "AES", "3DES"], 
        'digest': ["SHA-256", "SHA-384", "SHA-512"]
    }
    req = send('POST', 'api/protocols', message)
    cipher = req.json().get('cipher')
    mode = req.json().get('mode')
    digest = req.json().get('digest')

    if not parameters:
        parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())  
        parameter_numbers = parameters.parameter_numbers()
        message = {
            'type': 'DH_INIT',
            'p': parameter_numbers.p, 
            'g': parameter_numbers.g
        }
        req = send('POST', 'api/protocols', message)
        response = req.json()

    if not private_key:
        # generate a secret key
        private_key = parameters.generate_private_key()

        # generate the public key based on the private one -> g^(private_key) mod p 
        public_key = private_key.public_key()
        message = {
            'type': 'KEY_EXCHANGE',
            'public_key': public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode() 
        }
        req = send('POST', 'api/protocols', message)

    server_public_key = load_pem_public_key(response.get('public_key').encode(), backend=default_backend())
    shared_secret = private_key.exchange(server_public_key)

    logger.debug(f'Got shared secret: {shared_secret}')

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
    


    ##############################################################################################




    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == '200':
        print("Got Server List")

    media_list = req.json()


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
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)

#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import base64
import json
import os
import uuid
import math
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }
USERS = { 'miri': 
            {
                'name': 'Mariana Ladeiro',
                'email': 'marianaladeiro@ua.pt',
                'password': b'\xd4\x04U\x9f`.\xabo\xd6\x02\xacv\x80\xda\xcb\xfa\xad\xd1603^\x95\x1f\tz\xf3\x90\x0e\x9d\xe1v\xb6\xdb(Q/.\x00\x0b\x9d\x04\xfb\xa5\x13>\x8b\x1cn\x8d\xf5\x9d\xb3\xa8\xab\x9d`\xbeK\x97\xcc\x9e\x81\xdb'
            }
        }
CATALOG_BASE = 'catalog'
LICENSE_BASE = 'licenses'
CHUNK_SIZE = 1024 * 4
KEY_ROTATION_NR = 20

class MediaServer(resource.Resource):   

    def __init__(self):
        self.isLeaf = True
        self.derived_key = None
        self.cipher = None
        self.mode = None
        self.digest = None
        self.count = 0

        # server certficate
        with open('certificates/media_cert.pem','rb') as f:
            crt_data = f.read()

        self.certificate = x509.load_pem_x509_certificate(crt_data, default_backend())

        # server CA private and public key 
        with open("certificates/media_key.pem", "rb") as key_file:
            self.ca_private_key = load_pem_private_key(
                key_file.read(),
                password=None,
            )
        self.ca_public_key = self.ca_private_key.public_key()

    # Send the list of media files to clients
    def do_list(self, request):

        token = request.getHeader(b'Authorization')
        logger.debug(f'Received token: {token}')

        if token is None:

            request.setResponseCode(401)
            message = {
                'type': 'ERROR',
                'error': 'Not authorized' 
            }
            return self.send(message)


        auth = self.authenticate_token(token)
        if not auth:

            request.setResponseCode(401)
            message = {
                'type': 'ERROR',
                'error': 'Not authorized!' 
            }
            return self.send(message)

        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        message = {
            'data': media_list
        }

        # return json.dumps(media_list, indent=4).encode('latin')
        return self.send(message)

    def send(self, message):
        """
        Method used to encode and send a message to the client

        @param: message The message to encode
        @return The encoded message, with the encryped data, the iv in full and the MAC  
        """

        # Secure connection, after session keys are generated
        if self.derived_key and self.cipher:
            logger.debug(f"send via secure connection")
            cryptogram, iv = self.encrypt(json.dumps(message).encode('latin'))
            
            message = {
                'type': 'SECURE_MSG',
                'data': binascii.b2a_base64(cryptogram).decode(),
                'iv' : binascii.b2a_base64(iv).decode()
            }

            mac = self.mac(json.dumps(message).encode('latin'))

            message = {
                'type': "MAC_MSG",
                'mac': binascii.b2a_base64(mac).decode(),
                'data':  json.dumps(message),
            }

            self.count += 1

        return json.dumps(message).encode('latin')

    def encrypt(self, text):
        """
        Encrypt a text messages based on the ciphers and modees decided on the negotiation

        @param: text The text in bytes to enctypt
        @return The cryptogram of the text using the derived key
        @return The iv generated
        """
        iv = None
        if self.cipher == "ChaCha20":
            key = self.derived_key[:32]
            iv = os.urandom(16)
            algorithm = algorithms.ChaCha20(key, iv)
        elif self.cipher == "AES":
            key = self.derived_key[:16]
            algorithm = algorithms.AES(key)
        elif self.cipher == "3DES":
            key = self.derived_key[:8]
            algorithm = algorithms.TripleDES(key)

        # ChaCha20 is not a block cipher
        if self.cipher == "ChaCha20":
            cipher = Cipher(algorithm, mode=None, backend=default_backend())

        # Handle modes in block ciphers
        else:
            
            if self.mode == 'CBC':
                iv = os.urandom(int(algorithm.block_size / 8))
                mode = modes.CBC(iv)
            elif self.mode == 'GCM':
                iv = os.urandom(int(algorithm.block_size / 8))
                mode = modes.GCM(iv)
            elif self.mode == 'ECB':
                mode = modes.ECB() 

            padder = padding.PKCS7(algorithm.block_size).padder()
            text = padder.update(text) + padder.finalize()
            
            cipher = Cipher(algorithm=algorithm, mode=mode, backend=default_backend())   
            
        encryptor = cipher.encryptor()
        cryptogram = encryptor.update(text) + encryptor.finalize()
        return cryptogram, iv

    def mac(self, message):
        """
        Method used to hash the MAC to authenticate a message
        
        @param The message as bytes to hash and authenticate.
        @return The message digest as bytes
        """

        # Slice key based on algorithm
        if self.cipher == "ChaCha20":
            key = self.derived_key[:32]
        elif self.cipher == "AES":
            key = self.derived_key[:16]
        elif self.cipher == "3DES":
            key = self.derived_key[:8]

        # select the hash algoritm defined in the negotiations
        if self.digest == 'SHA-256':
            hash_algorithm = hashes.SHA256()
        elif self.digest == 'SHA-384':
            hash_algorithm = hashes.SHA384()
        elif self.digest == 'SHA-512':
            hash_algorithm = hashes.SHA512()

        digest = hmac.HMAC(key=key, algorithm=hash_algorithm, backend=default_backend())
        digest.update(message)
        return digest.finalize()

    def do_get_protocols(self, request):
        """
        Processes the GET request to the protocols endpoint

        @oaram: request The request tht came from the client in bytes
        @return The response, in bytes, to the client
        """

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        message = {
            'type': 'PROTOOCOLS',
            'data': {'negotiate': 'NEGOTIATE', 'dh_init': 'DH_INIT'}
        }
        return self.send(message)

    def do_post_protocols(self, request):
        """
        Processes a POST request to the protocols endpoint based on the type of message

        @oaram: request The request that came from the client in bytes
        @return The encrypted response sent to the client
        """

        # TODO: authenticate the request

        if (request.args.get(b'type')):
            msg_type = request.args.get(b'type')[0]
        else:
            msg_type = None

        if msg_type == b'NEGOTIATE':

            self.derived_key = None
            # choose the alortithm and mode
            if self.choose_suite(request.args.get(b'cipher'), request.args.get(b'mode'), request.args.get(b'digest')):
                request.setResponseCode(200)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                message = {
                    'type': 'NEGOTIATE',
                    'mode': self.mode,
                    'cipher': self.cipher, 
                    'digest': self.digest
                }
                return self.send(message)

            
            else:
                request.setResponseCode(501)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                message = {
                    'type': 'ERROR',
                    'error': 'invalid suite'
                }
                return self.send(message)

    def choose_suite(self, ciphers, modes, digests):
        """
        Algorithm used to choose and set the MediaServer's cipher, mode and digest based on
        which combination of the client's avalable one is the most secure

        @param: ciphers A list of the client's available cipher algorithms
        @param: modes A list of the client's available modes to cipher
        @param: diigests A list of the client's available digest algorithms 
        @return True if a suite has been successefully chosen, False otherwise
        """

        # choose cipher
        if b'ChaCha20' in ciphers:
            self.cipher = 'ChaCha20'
        elif b'3DES' in ciphers:
            self.cipher = '3DES'
        elif b'AES' in ciphers:
            self.cipher = 'AES'
        else:
            logger.error("Algorithm not supported")
            return False

        # choose modes:
        if b'GCM' in modes and self.cipher == "AES":
            self.mode = 'GCM'
        elif b'CBC' in modes:
            self.mode = 'CBC'
        elif b'ECB' in modes:
            self.mode = 'ECB'
        else:
            logger.error("Mode not supported")
            return False

        # choose digest
        if b'SHA-512' in digests:
            self.digest = 'SHA-512'
        elif b'SHA-384' in digests:
            self.digest = 'SHA-384'
        elif b'SHA-256' in digests:
            self.digest = 'SHA-256'
        else:
            logger.error("Digest not supported")
            return False

        return True

    def do_dh_exchange(self, request):
        """
        Processes a POST request to the api/key endpoint, which triggeres the Diffie-Hellman's 
        key generation process that generates the p and g parameters, generates a private key 
        and a shared secret, as well as deriving the latter in order to create ephemeral keys
        for each session.
        This process is then repeated when the number of received messages from the client surpasses 20,
        to assure key rotation and therefore a extra level of security.  

        @param: request Request that come from the client in bytes
        @return The encrypted response sent to the client
        """

        msg_type = None
        if (request.args.get(b'type')):
            msg_type = request.args.get(b'type')[0]

        if msg_type == b'DH_INIT':
            p = int(request.args.get(b'p')[0].decode())
            g = int(request.args.get(b'g')[0].decode())

            self.parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())

            # generate a secret key
            self.private_key = self.parameters.generate_private_key()

            # generate the public key based on the private one -> g^(private_key) mod p 
            self.public_key = self.private_key.public_key()

            request.setResponseCode(200)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = {
                'type': 'DH_INIT',
                'public_key': self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode() 
            }
            return self.send(message)

        elif msg_type == b'KEY_EXCHANGE':

            client_public_key = load_pem_public_key(request.args.get(b'public_key')[0], backend=default_backend())
            shared_secret = self.private_key.exchange(client_public_key)

            logger.debug(f'Got shared secret: {shared_secret}')

            if self.digest == 'SHA-256':
                algorithm = hashes.SHA256()
            elif self.digest == 'SHA-384':
                algorithm = hashes.SHA384()
            elif self.digest == 'SHA-512':
                algorithm = hashes.SHA512()

            # Derive key
            self.derived_key = HKDF(
                algorithm = algorithm,
                length = algorithm.digest_size,
                salt = None,
                info = b'handshake',
                backend = default_backend()
            ).derive(shared_secret)

            logger.debug(f'Got derived_key: {self.derived_key}')
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = {
                'type': 'OK',
                'data': {}
            }

            return self.send(message)

    def do_regen_key(self, request):
        """
        Method called when the number of messages from the client reaches a certain number,
        in order to assure key rotation, the triggers the Diffie-Hellman's process to generate
        new ephemeral key, generating a new set of private and public keys, both on the client
        and the server's side.

        @param: request Request that comes from the client in bytes
        @return The encrypted response sent to the client    
        """

        last_chunk = request.args.get(b'chunk', [b'0'])[0].decode()
        message = {
            'type': 'REGEN_KEY',
            'last_chunk': last_chunk
        }
        return self.send(message)

    def authenticate_token(self, token):
        """
        Method called to authenticate the token received when the client does a request to 
        the server. It uses the digest of an unique id and then verifies if the token is
        authentic by comparing it with the signature

        @param: token Token receiven in the header of the request
        @return True if the token if the token is authenticated, False otherwise.
        """
        token = binascii.a2b_base64(token)

        # Slice key based on algorithm
        if self.cipher == "ChaCha20":
            key = self.derived_key[:32]
        elif self.cipher == "AES":
            key = self.derived_key[:16]
        elif self.cipher == "3DES":
            key = self.derived_key[:8]

        # select the hash algoritm defined in the negotiations
        if self.digest == 'SHA-256':
            algorithm = hashes.SHA256()
        elif self.digest == 'SHA-384':
            algorithm = hashes.SHA384()
        elif self.digest == 'SHA-512':
            algorithm = hashes.SHA512()

        digest = hmac.HMAC(key, algorithm, backend=default_backend())
        digest.update(self.uuid.encode('latin'))
        
        try:
            digest.verify(token)
            return True
        except:
            return False

    def do_authentication(self, request):
        """
        Method used to create a token based on the login request made by the user. First compares
        the received hash with the one stored in the simulated database (USERS) and if its the same
        creates a token for authentication and send it to the client.

        @param: request The request that is received from the client
        @return The response sent to the client 
        """

        data = request.args.get(b'data')[0]
        username = request.args.get(b'username')[0].decode()
        logger.debug(f'Received data: {data}')

        if USERS.get(username):

            if USERS.get(username).get('password') == data:
                
                # generating token
                if self.cipher == "ChaCha20":
                    key = self.derived_key[:32]
                elif self.cipher == "AES":
                    key = self.derived_key[:16]
                elif self.cipher == "3DES":
                    key = self.derived_key[:8]

                # select the hash algoritm defined in the negotiations
                if self.digest == 'SHA-256':
                    hash_algorithm = hashes.SHA256()
                elif self.digest == 'SHA-384':
                    hash_algorithm = hashes.SHA384()
                elif self.digest == 'SHA-512':
                    hash_algorithm = hashes.SHA512()

                digest = hmac.HMAC(key=key, algorithm=hash_algorithm, backend=default_backend())
                self.uuid = uuid.uuid4().hex
                digest.update(self.uuid.encode('latin'))
                token = digest.finalize()

                message = {
                    'type': 'SUCESS_AUTH',
                    'data': binascii.b2a_base64(token).decode()
                }
                return self.send(message)

            else:
                logger.debug('Authentication failed - wrong password')
                message = {
                    'type': 'ERROR',
                    'error': 'Authentication failed'
                }
                return self.send(message)
        else:
            logger.debug('Authentication failed - no such user')
            message = {
                    'type': 'ERROR',
                    'error': 'Authentication failed'
            }
            return self.send(message)

    def check_license(self, media_id, chunk_id):
        """
        Check if a client has a viewing license for a speciffic media by reading the respective
        media's file license and checking if the client is listed and if the licence is valid.
        While it searches for the client's license, this method also deletes expired licenses in
        order to improve performance.

        @param: media_id The id of media the client wants to play
        @retur True if the license is valid, False otherwise
        """

        with open(os.path.join(LICENSE_BASE, media_id), 'rb+') as f:
            f.write(binascii.b2a_base64("miri\t2021-12-30 12:00:00.000\t10000\t200\n".encode('latin')))
            f.seek(0)

            valid = None
            d = f.readlines()
            f.seek(0)

            for line in d:
                line = binascii.a2b_base64(line).decode()
                client_id = 'miri'
                _line = line.strip().split('\t')

                if client_id == _line[0]:
                    if datetime.datetime.strptime(_line[1], '%Y-%m-%d %H:%M:%S.%f') + datetime.timedelta(seconds= int(_line[2])) < datetime.datetime.now() and valid != True:
                        # The licence date expired
                        valid = False

                    elif chunk_id == b'1' and int(_line[3]) <= 0 and valid != True:
                        # The number of views expired
                        valid = False

                    else:
                        # There is a valid license in the client's name
                        new_line = f'{_line[0]}\n{_line[1]}\n{_line[2]}\n{int(_line[3])- 1}'.encode('latin')
                        f.write(binascii.b2a_base64(new_line))
                        valid = True
                
                else:
                    f.write(binascii.b2a_base64(line.encode('latin')))
                    
            if valid is None:
                logger.debug('Client has no rights to view this content')
                valid = False

            f.truncate()
            f.close()
        
        return valid

    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if token is in the header
        token = request.getHeader(b'Authorization')
        if token is None:
            request.setResponseCode(401)
            message = {
                'type': 'ERROR',
                'error': 'Not authorized' 
            }
            return self.send(message)

        # Check if token is valid
        auth = self.authenticate_token(token)
        if not auth:
            request.setResponseCode(401)
            message = {
                'type': 'ERROR',
                'error': 'Not authorized' 
            }
            return self.send(message)

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Check licenciong
        if not self.check_license(media_id, chunk_id):
            request.setResponseCode(403)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'No access rights to the content'}).encode('latin')

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    }
            return self.send(message)

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        
        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':

                # Chunk based key rotation
                if self.count == KEY_ROTATION_NR:
                    self.count = 0
                    logger.debug("Regenning keys for key rotation..")
                    return self.do_regen_key(request)
                
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        if request.path == b'/api/protocols':
            return self.do_post_protocols(request)
        elif request.uri == b'/api/key':
            return self.do_dh_exchange(request)
        elif request.uri == b'/api/auth':
            return self.do_authentication(request)

        request.setResponseCode(501)
        return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()

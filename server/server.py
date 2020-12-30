#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import base64
import json
import os
import math
import datetime

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key
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

CATALOG_BASE = 'catalog'
LICENSE_BASE = 'licenses'
CHUNK_SIZE = 1024 * 4
KEY_ROTATION_NR = 20

class MediaServer(resource.Resource):
    isLeaf = True
    derived_key = None
    cipher = None
    count = 0

    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


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
        This process is then repeated when the number received messages from the client surpasses 20,
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

        self.parameters = None
        self.private_key = None
        self.derived_key = None
        last_chunk = request.args.get(b'chunk', [b'0'])[0].decode()
        message = {
            'type': 'REGEN_KEY',
            'last_chunk': last_chunk
        }
        return self.send(message)

    def check_license(self, media_id):
        """
        Check if a client has a viewing license for a speciffic media by reading the respective
        media's file license and checking if the client is listed and if the licence is valid.
        While it searches for the client's license, this method also deletes expired licenses in
        order to improve performance.

        @param: media_id The id of media the client wants to play
        @retur True if the license is valid, False otherwise
        """

        with open(os.path.join(LICENSE_BASE, media_id), 'rb+') as f:
            # f.write(binascii.b2a_base64("0001\t1978-10-2 12:12:12.000\t10\n".encode('latin')))
            # f.write(binascii.b2a_base64("0001\t2020-12-30 12:00:00.000\t10000\n".encode('latin')))
            # f.seek(0)

            valid = None
            d = f.readlines()
            f.seek(0)

            for line in d:
                line = binascii.a2b_base64(line)
                client_id = b'0001'
                _line = line.strip().split(b'\t')

                if client_id == _line[0]:
                    if datetime.datetime.strptime(_line[1].decode(), '%Y-%m-%d %H:%M:%S.%f') + datetime.timedelta(seconds= int(_line[2].decode())) < datetime.datetime.now():
                        if valid != True:
                            logger.debug('This viewing license expired')
                            valid = False
                    else:
                        # There is a valid and not expired license in the client's name
                        f.write(binascii.b2a_base64(line))
                        valid = True
                
                else:
                    f.write(binascii.b2a_base64(line))
                    if valid != True:
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

        # Check licenciong
        if not self.check_license(media_id):
            request.setResponseCode(403)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'No access rights to the content'}).encode('latin')

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
        
        if self.count == KEY_ROTATION_NR:
            self.count = 0
            logger.debug("Regening keys for key rotation..")
            return self.do_regen_key(request)


        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            #elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
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
        request.setResponseCode(501)
        return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()

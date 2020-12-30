# Digital Rights Management
This work aims to explore concepts associated with a secure media player,
which enables clients to consume media content from a catalog, while enforcing strong restrictions through the use of cryptographic primitives. The
overall project is split into two parts, which should be executed in sequence.
The first part will consider the establishment of a secure session between the
player and the server, while the second part will deal with authentication,
access control and confinement.

## Setup
1. Install ffmepeg 
```bash
$ sudo apt install ffmpeg
```

2. Install and create a virtual environment
```bash
$ apt install virtualenv
$ virtualenv -p python3 venv
```

3. Activate the virtual environment
```bash
$ source ./venv/bin/activate
```

4. Install the requirements
```bash
$ pip3 install -r client/requirements.txt
$ pip3 install -r server/requirements.txt
```

5. Run each script in a different terminal

## Main Objectives
### Confidentiality and Integrity
1. Negotiate a cipher suite between the client and server (at least 2
ciphers, 2 digests, 2 cipher modes)
2. Negotiate ephemeral keys between the client and server (valid only for
a single session)
3. Encrypt all communications
4. Validate the integrity of all messages and chunks
5. Manage cryptographic viewing licenses, based on time or number of
views
6. Provide the means for chunk based key rotation

### Authentication and Isolation
1. Mutually authenticate the client and server supported by a custom
PKI
2. Authenticate the user viewing the media content
3. Authenticate the content viewed so that the client can verify the con-
tent authenticity
4. Integrate hardware tokens to authenticate users
5. Protect the media content at rest in the server

### Report
The report describes the protocols in detail (entities, messages, keys, processes, flows), the mechanisms, and demonstrate the correct operation of the features implemented.

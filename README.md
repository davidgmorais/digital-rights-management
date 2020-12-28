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

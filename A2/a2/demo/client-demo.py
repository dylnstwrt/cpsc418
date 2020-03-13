#!/usr/bin/env python3

# Client socket program

import socket
import sys, os
import sympy
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
HOST = '127.0.0.1'  # The server's hostname or IP address. This is the local host address
PORT = 65432        # The port used by the server, usually between 0 - 65535. Lower ports may be resrved



# Ask for username via standard input

print("Please enter a username: ")
uname = sys.stdin.readline()
# encode it as bytes, and record the length
unamebytes = uname.encode('utf-8')
# convert store the length in a 4byte array in big-endian
unamelength = len(unamebytes).to_bytes(4, 'big')

#creates client string to be sent
clientdata = unamelength + unamebytes

print("Please enter a password: ")
upassword = sys.stdin.readline()
upasswordbytes = uname.encode('utf-8')

salt = os.urandom(16)

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(salt+upasswordbytes)
x = digest.finalize()

# create socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    #connect to server
    conn.connect((HOST, PORT))

    # Receive parameters from server
    conn.send(clientdata)

    server_response = conn.recv(1024)
    print((server_response.decode('utf-8')))







#print('Received', repr(data))

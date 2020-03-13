#!/usr/bin/env python3

# Client socket program

import socket
import sys, os
import sympy
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
HOST = '127.0.0.1'  # The server's hostname or IP address. This is the local host address
PORT = 65432        # The port used by the server, usually between 0 - 65535. Lower ports may be resrved



# Ask for username via standard input
def main():
    print("Please enter a username: ")
    uname = sys.stdin.readline()
    # encode it as bytes, and record the length
    unamebytes = uname.encode('utf-8')
    # convert store the length in a 4byte array in big-endian
    unamelength = len(unamebytes).to_bytes(4, 'big')

    print("Please enter a password: ")
    upassword = sys.stdin.readline()
    upasswordbytes = upassword.encode('utf-8')

    salt = os.urandom(16)

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt+upasswordbytes)
    x = int.from_bytes(digest.finalize(), 'big')

    # create socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        
        N = int.from_bytes(conn.recv(64), 'big')
        g = int.from_bytes(conn.recv(64), 'big')
        
        v = pow(g,x,N).to_bytes(64, 'big')
        
        conn.sendall(b'r')
        conn.sendall(unamelength)
        conn.sendall(unamebytes)
        conn.sendall(salt)
        conn.sendall(v)
        
        x = None
        
        conn.close()
    
    time.sleep(0.5)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        

if __name__ == "__main__":
    main()






#print('Received', repr(data))

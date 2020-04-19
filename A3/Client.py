#!/usr/bin/env python3

'''
File: Client.py
Class: CPSC418 - Winter 2020
Name: Dylan Stewart
UCID: 30024193
Assignment : 2
Problem: 9
'''

import socket
import sys, os
import sympy
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
HOST = '127.0.0.1'  # The server's hostname or IP address. This is the local host address
PORT = 31803       # The port used by the server, usually between 0 - 65535. Lower ports may be resrved
    
def genRand(prime):
    upperBound = prime - 2
    return secrets.SystemRandom().randint(0, upperBound)

def hashBytes(bytesToHash):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(bytesToHash)
    return digest.finalize()
    
def main():
    print("Please enter a username: ")
    uname = sys.stdin.readline()
    uname = uname.strip('\n')
    # encode it as bytes, and record the length
    unamebytes = uname.encode('utf-8')
    # convert store the length in a 4byte array in big-endian
    unamelength = len(unamebytes).to_bytes(4, byteorder='big')
    
    print("Please enter a password: ")
    upassword = sys.stdin.readline()
    upassword = upassword.strip('\n')
    upasswordbytes = upassword.encode('utf-8')

    salt = os.urandom(16)

    x = int.from_bytes(hashBytes(salt+upasswordbytes), byteorder='big')
    print("Client: I = \'"+uname+"\'", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        # Connect to TTP
        conn.connect((HOST, 31802))
        conn.sendall(b'REQUEST KEY')
        ttp_n = int.from_bytes(conn.recv(128),byteorder='big')
        tpp_e = int.from_bytes(conn.recv(128),byteorder='big')
        conn.close()
        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        
        v = pow(g,x,N).to_bytes(64, byteorder='big')
        conn.sendall(b'r')
        conn.sendall(unamelength+unamebytes)
        conn.sendall(salt)
        conn.sendall(v)
        del x
        print("Client: Registration Successful", flush=True)
        conn.close()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST, PORT))
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        conn.sendall(b'p')
        conn.sendall(unamelength+unamebytes)
        servername_length = int.from_bytes(conn.recv(4), byteorder='big')
        servername_bytes = conn.recv(servername_length)
        Server_N = conn.recv(128)
        Server_e = conn.recv(128)
        ttp_sig = int.from_bytes(conn.recv(128), byteorder='big')
        
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(servername_bytes+Server_N+Server_e)
        t = digest.finalize()
        
        digest2 = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest2.update(t)
        t_naught = digest2.finalize()
        t_naught = int.from_bytes(t_naught, byteorder='big') % ttp_n
        if(t_naught == pow(ttp_sig, tpp_e, ttp_n)):
            print("Verified")
        else:
            print("Unverified")
            conn.close()
        
        # here be issues, generating and sending A incorrectly
        
        
if __name__ == "__main__":
    main()
#print('Received', repr(data))
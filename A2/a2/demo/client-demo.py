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
    
    
def genRand(prime):
    upperBound = prime - 2
    return secrets.SystemRandom().randint(0, upperBound)

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
        
        del x
        
        conn.close()
    
    time.sleep(0.5)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        
        N = int.from_bytes(conn.recv(64), 'big')
        g = int.from_bytes(conn.recv(64), 'big')
        print(N)
        print(g)
        a = genRand(N)
        A = pow(g, a, N).to_bytes(64, 'big')
        print(A)
        
        conn.sendall(b'p')
        conn.sendall(unamelength)
        conn.sendall(unamebytes)
        conn.sendall(A)
        
        salt = conn.recv(16)
        B = conn.recv(64)
        print(B)
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(A+B)
        hashBytes = digest.finalize()
        u = int.from_bytes(hashBytes, 'big') % N
        
        print(u)
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(N.to_bytes(64,'big') + g.to_bytes(64, 'big'))
        hashBytes = digest.finalize()
        k = int.from_bytes(hashBytes, 'big')
        print(k)
        
        base = int.from_bytes(B, 'big') - (k*int.from_bytes(v, 'big'))
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(salt+upasswordbytes)
        x = int.from_bytes(digest.finalize(), 'big')
        
        K_client = 
        print(K_client)
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(A + B + K_client)
        M_1 = digest.finalize()
        
        conn.sendall(M_1)

if __name__ == "__main__":
    main()






#print('Received', repr(data))

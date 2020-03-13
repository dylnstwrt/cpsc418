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
    
def hashBytes(bytesToHash):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytesToHash)
    return digest.finalize()
    
    
# Ask for username via standard input
def main():
    print("Please enter a username: ")
    uname = sys.stdin.readline()
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

    # create socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        
        v = pow(g,x,N).to_bytes(64, byteorder='big')
        
        conn.sendall(b'r')
        conn.sendall(unamelength)
        conn.sendall(unamebytes)
        conn.sendall(salt)
        conn.sendall(v)
        print("Salt Generated :", salt)
        del x
        
        conn.close()
    
    time.sleep(0.5)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        print("N: ",N)
        print("g: ",g)
        a = genRand(N)
        A = pow(g, a, N).to_bytes(64, byteorder='big')
        print("A: ",A)
        #print(A)
        
        conn.sendall(b'p')
        conn.sendall(unamelength)
        conn.sendall(unamebytes)
        conn.sendall(A)
        
        salt = conn.recv(16)
        print("Salt Recv: ", salt)
        B = conn.recv(64)
        print("B: ", B)
        #print(B)
        
        u = int.from_bytes(hashBytes(A+B), byteorder='big') % N
        print("u", u)
        
        k = int.from_bytes(hashBytes(N.to_bytes(64,byteorder='big') + g.to_bytes(64, byteorder='big')), byteorder='big')
        print("k: ",k)
        
        x = int.from_bytes(hashBytes(salt+upasswordbytes), byteorder='big')
        
        
        K_client = pow((int.from_bytes(B, byteorder='big')%N) - ((k * int.from_bytes(v, byteorder='big'))%N), (a + (u*x)), N)
        print(K_client)
        
        M_1 = hashBytes(A + B + K_client.to_bytes(64,byteorder='big'))
        print("M_1: ",M_1)

if __name__ == "__main__":
    main()






#print('Received', repr(data))

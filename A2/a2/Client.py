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
HOST = '127.0.4.18'  # The server's hostname or IP address. This is the local host address
PORT = 31802        # The port used by the server, usually between 0 - 65535. Lower ports may be resrved
    
    
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
    # create socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        
        v = pow(g,x,N).to_bytes(64, byteorder='big')
        
        print("Client: Sending 'r' <"+bytes('r', 'utf-8').hex()+">", flush=True)
        conn.sendall(b'r')
        print("Client: Sending |I| <"+unamelength.hex()+">", flush=True)
        conn.sendall(unamelength)
        print("Client: Sending I <"+unamebytes.hex()+">", flush=True)
        conn.sendall(unamebytes)
        print("Client: s = <"+salt.hex()+">", flush=True)
        print("Client: Sending s <"+salt.hex()+">", flush=True)
        conn.sendall(salt)
        print("Client: v =",int.from_bytes(v, byteorder='big'), flush=True)
        print("Client: Sending v <"+v.hex()+">", flush=True)
        conn.sendall(v)
        del x
        print("Client: Registration successful.")
        conn.close()
    
    time.sleep(0.5)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        
        
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        a = genRand(N)
        A = pow(g, a, N).to_bytes(64, byteorder='big')
        
        print("Client: N =", N, flush=True)
        print("Client: g =", g, flush=True)
        print("Client: a =", a, flush=True)
        print("Client: A =", int.from_bytes(A, byteorder='big'), flush=True)
        
        print("Client: Sending 'p' <"+bytes('p', 'utf-8').hex()+">", flush=True)
        conn.sendall(b'p')
        print("Client: Sending |I| <"+unamelength.hex()+">", flush=True)
        conn.sendall(unamelength)
        print("Client: Sending I <"+unamebytes.hex()+">", flush=True)
        conn.sendall(unamebytes)
        print("Client: Sending A <"+A.hex()+">", flush=True)
        conn.sendall(A)
        
        salt = conn.recv(16)
        print("Client: s =<"+salt.hex()+">", flush=True)
        B = conn.recv(64)
        print("Client: B =",int.from_bytes(B, byteorder='big'), flush=True)
        
        u = int.from_bytes(hashBytes(A+B), byteorder='big') % N
        print("Client: u =", u, flush=True)
        
        k = int.from_bytes(hashBytes(N.to_bytes(64,byteorder='big') + g.to_bytes(64, byteorder='big')), byteorder='big')
        print("Client: k =", k, flush=True)
        
        x = int.from_bytes(hashBytes(salt+upasswordbytes), byteorder='big')
        
        
        k_client = pow((int.from_bytes(B, byteorder='big')%N) - ((k * int.from_bytes(v, byteorder='big'))%N), (a + (u*x)), N)
        print("Client: k_client =", k_client, flush=True)
        
        M_1 = hashBytes(A + B + k_client.to_bytes(64,byteorder='big'))
        print("Client: M1 = <"+M_1.hex()+">", flush=True)
        print("Client: Sending M1 <"+M_1.hex()+">",flush=True)
        conn.sendall(M_1)
        M_2 = hashBytes(A + M_1 + k_client.to_bytes(64, byteorder='big'))
        M_2_Recv = conn.recv(64)
        print("Client: M2 = <"+M_2_Recv.hex()+">", flush=True)
        if (M_2_Recv == M_2):
            print("Client: Negotiation successful", flush=True)
        else:
            print("Client: Negotiation unsuccessful", flush=True)
        conn.close()
        
        
if __name__ == "__main__":
    main()
#print('Received', repr(data))
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

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.0.1'  # The server's hostname or IP address. This is the local host address
PORT = 31803       # The port used by the server, usually between 0 - 65535. Lower ports may be resrved
    
def genRand(prime):
    upperBound = prime - 2
    return secrets.SystemRandom().randint(0, upperBound)

def hashBytes(bytesToHash):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(bytesToHash)
    return digest.finalize()
    
def keygen(password):
    long_key = hashBytes(password.to_bytes(64, byteorder='big'))
    #long_key = sha1_digest(password)
    key = bytearray(32)
    for i in range(32):
        key[i] = long_key[i]
    return key
    
def main():
    """
    if (len(sys.argv) != 2):
        print("Usage: Client.py <inFilename>")
        exit(-1)
    """
        
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
        a = genRand(N)
        A = pow(g,a,N)
        enc_A = pow(A, int.from_bytes(Server_e,byteorder='big'), int.from_bytes(Server_N, byteorder='big'))
        conn.sendall(enc_A.to_bytes(128, byteorder='big'))
        salt = conn.recv(16)
        B = int.from_bytes(conn.recv(64), byteorder='big')
        N_bytes = N.to_bytes(64, byteorder='big')
        g_bytes = g.to_bytes(64, byteorder='big')
        to_hash = N_bytes + g_bytes
        k = int.from_bytes(hashBytes(to_hash), byteorder='big')
        x = int.from_bytes(hashBytes(salt+upasswordbytes), byteorder='big')
        u = int.from_bytes(hashBytes(A.to_bytes(64, byteorder='big') + B.to_bytes(64, byteorder='big')), byteorder='big') % N
        k_client = pow((int.from_bytes(B.to_bytes(64, byteorder='big'), byteorder='big')%N) - ((k * int.from_bytes(v, byteorder='big'))%N), (a + (u*x)), N)
        print(k_client)
        
        M_1 = hashBytes(A.to_bytes(64, byteorder='big') + B.to_bytes(64, byteorder='big') + k_client.to_bytes(64,byteorder='big'))
        conn.sendall(M_1)
        M_2 = hashBytes(A.to_bytes(64, byteorder='big') + M_1 + k_client.to_bytes(64, byteorder='big'))
        if (M_2 == conn.recv(64)):
            print("YES")
        else:
            print("Client: Negotiation unsuccessful", flush=True)
            conn.close()
        
        fd = open(sys.argv[1])
        byteArr = bytearray(fd.read(), "utf-8")
        fd.close()
        
        tag = hashBytes(byteArr)
        print(len(tag))
        extended_byteArr = byteArr + tag
        #print(extended_byteArr)
        key = keygen(k_client)
        iv = os.urandom(16)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bytes(extended_byteArr))
        padded_data += padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext =  encryptor.update(padded_data) + encryptor.finalize()
        
        forTransfer = iv + ciphertext
        
        size = len(ciphertext).to_bytes(4, byteorder='big')
        
        conn.sendall(size + forTransfer)
        
        
        
if __name__ == "__main__":
    main()
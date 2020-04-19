#!/usr/bin/env python3

'''
File: Server.py
Class: CPSC418 - Winter 2020
Name: Dylan Stewart
UCID: 30024193
Assignment : 3
Problem: 8
'''

import socket
import sys
import os
import sympy
import secrets
import time

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 31803        # Port to listen on (non-privileged ports are > 1023)

def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

#review/understand better
def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    return x % b
    

def generatePrime():
    while True:
        q = secrets.randbits(511)
        while True:
            if sympy.isprime(q):
                break
            else:
                if (q % 2 == 0):
                    q = q + 1
                q = q + 2
        N = (2*q) + 1
        if sympy.isprime(N):
            return N

def generate_RSA_Prime(size):
    p = secrets.randbits(size)
    while True:
        if sympy.isprime(p):
            return p
        else:
            if (p % 2 == 0):
                p = p + 1
            p = p + 2

def gen_rsa_pub(phi_n):
    while True:
        e = secrets.randbelow(phi_n)
        if (e >= 1) & (sympy.gcd(e, phi_n) == 1):
            return e
            
def calculatePrimRoots(num):
    for i in range(1, num, 1):
        if sympy.is_primitive_root(i, num):
            return i
            
def hashBytes(bytesToHash):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(bytesToHash)
    return digest.finalize()
    
def genRand(prime):
    upperBound = prime - 2
    return secrets.SystemRandom().randint(0, upperBound)

def rsa_keygen():
    p = generate_RSA_Prime(512)
    q = generate_RSA_Prime(512)
    n = p*q
    phi_n = (p - 1)*(q - 1)
    e = gen_rsa_pub(phi_n)
    d = modinv(e, phi_n)
    return e, d, n

def keygen(password):
    long_key = hashBytes(password.to_bytes(64, byteorder='big'))
    #long_key = sha1_digest(password)
    key = bytearray(32)
    for i in range(32):
        key[i] = long_key[i]
    return key

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def main():
    """
    if (len(sys.argv) != 2):
        print("Usage: Server.py <outFilename>")
        exit(-1)
    """
    print("Please enter a server name: ")
    server_name = sys.stdin.readline()
    server_name = server_name.strip('\n')
    
    server_name_bytes = server_name.encode('utf-8')
    server_name_length = len(server_name_bytes).to_bytes(4, byteorder='big')
    
    saltDict = dict()
    vDict = dict()
    
    ##### RSA #####
    Server_e, d, Server_N = rsa_keygen()
    
    ##### Key Exchange #####
    N = generatePrime()
    g = calculatePrimRoots(N)
    
    # @327 Piazza
    pk_server = Server_N.to_bytes(128, byteorder='big') + Server_e.to_bytes(128, byteorder='big')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST,31802))
        conn.sendall(b"REQUEST SIGN")
        time.sleep(1)
        conn.sendall(server_name_length+server_name_bytes+pk_server)
        ttp_N = conn.recv(128)
        ttp_Sig = conn.recv(128)
        conn.close()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        while True:
            print("Server Listening...")
            s.listen()
            conn, addr = s.accept()
            with conn:
                publicBytes =  N.to_bytes(64, byteorder='big') + g.to_bytes(64, byteorder='big')
                conn.sendall(publicBytes)
                switch = conn.recv(1).decode('utf-8')
                length = int.from_bytes(conn.recv(4), byteorder='big')
                uname = conn.recv(length)
                user = uname.decode('utf-8')
                user = user.strip('\n')
                if switch == 'r':
                    salt = conn.recv(16)
                    v = int.from_bytes(conn.recv(64), byteorder='big')
                    saltDict.update({user: salt})
                    vDict.update({user: v})
                if switch == 'p':
                    salt = saltDict.get(user)
                    v = vDict.get(user)
                    # account in client for N, g being sent each time
                    cert = server_name_length+server_name_bytes+pk_server+ttp_Sig
                    conn.sendall(cert)
                    enc_A = int.from_bytes(conn.recv(128), byteorder='big')
                    
                    A = rsa_decrypt(enc_A, d, Server_N)
                    
                    b = genRand(N)
                    N_bytes = N.to_bytes(64, byteorder='big')
                    g_bytes = g.to_bytes(64, byteorder='big')
                    to_hash = N_bytes + g_bytes
                    k = int.from_bytes(hashBytes(to_hash), byteorder='big')
                    
                    B_int = (((k*v)%N) + pow(g,b,N))%N
                    B = B_int.to_bytes(64, byteorder='big')
                    conn.send(salt)
                    conn.sendall(B)
                    
                    u = int.from_bytes(hashBytes(A.to_bytes(64, byteorder='big') + B), byteorder='big') % N
                    k_server = pow(((int.from_bytes(A.to_bytes(64, byteorder='big'), byteorder='big') % N) * pow(v,u,N)), b, N)
                    
                    M_1 = hashBytes(A.to_bytes(64, byteorder='big') + B + k_server.to_bytes(64,byteorder='big'))
                    
                    if (M_1 == conn.recv(64)):
                        M_2 = hashBytes(A.to_bytes(64, byteorder='big') + M_1 + k_server.to_bytes(64, byteorder='big'))
                        conn.sendall(M_2)
                    else:
                        conn.sendall(M_1)
                        print("Server: Negotiation unsucessful",flush=True)
                        conn.close()
                    
                    size = int.from_bytes(conn.recv(4), byteorder='big')
                    iv = conn.recv(16)
                    ciphertext = conn.recv(size)
                    
                    key = keygen(k_server)
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                    unpadder = padding.PKCS7(128).unpadder()
                    message = unpadder.update(plaintext)
                    message += unpadder.finalize()
                    
                    offset = len(message) - 32
                    plaintext = message[:offset]
                    tag = message[offset:]
                    
                    print(message)
                    print(plaintext)
                    print(tag)
                    
                    if (tag == hashBytes(plaintext)):
                        print("Match")
                        output = open("PTXT", "wb")
                        output.write(plaintext)
                        output.close()
                    
if __name__ == "__main__":
    main()
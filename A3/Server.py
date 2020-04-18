#!/usr/bin/env python3

'''
File: Server.py
Class: CPSC418 - Winter 2020
Name: Dylan Stewart
UCID: 30024193
Assignment : 2
Problem: 9
'''

import socket
import sys
import os
import sympy
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 31802        # Port to listen on (non-privileged ports are > 1023)

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

def generatePrime(size):
    p = secrets.randbits(size)
    while True:
        if sympy.isprime(p):
            return p
        else:
            if (p % 2 == 0):
                p = p + 1
            p = p + 2

def gen_public(phi_n):
    while True:
        e = secrets.randbelow(phi_n)
        if (e >= 1) & (sympy.gcd(e, phi_n) == 1):
            return e

def main():
    
    p = generatePrime(512)
    q = generatePrime(512)
    n = p*q
    phi_n = (p - 1)*(q - 1)
    e = gen_public(phi_n)
    d = modinv(e, phi_n)
    
    # what do we consider to be pk_server????
    # e is the public key for RSA????
    pk_server = n.to_bytes(128, byteorder='big') + e.to_bytes(128, byteorder='big')
    
    print("Please enter a server name: ")
    server_name = sys.stdin.readline()
    server_name = server_name.strip('\n')
    
    server_name_bytes = server_name.encode('utf-8')
    server_name_length = len(server_name_bytes).to_bytes(4, byteorder='big')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST,PORT))
        conn.sendall(b"REQUEST SIGN")
        time.sleep(1)
        conn.sendall(server_name_length+server_name_bytes+pk_server)
        tpp_n = conn.recv(128)
        tpp_sig = conn.recv(128)
        conn.close()
        

if __name__ == "__main__":
    main()
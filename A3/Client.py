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
PORT = 31802        # The port used by the server, usually between 0 - 65535. Lower ports may be resrved
    
    
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
        
if __name__ == "__main__":
    main()
#print('Received', repr(data))
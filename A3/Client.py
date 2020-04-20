#!/usr/bin/env python3

'''
File: Client.py
Class: CPSC418 - Winter 2020
Name: Dylan Stewart
UCID: 30024193
Assignment : 3
Problem: 8
'''

import socket
import sys, os
import sympy
import secrets
import time

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.4.18'  # The server's hostname or IP address. This is the local host address
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
    
def rsa_encrypt(m, e, n):
    return pow(m, e, n)
    
def rsa_sig_verify(ttp_sig, ttp_e, ttp_n, servername_bytes, Server_N, Server_e):
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(servername_bytes+Server_N+Server_e)
    t = digest.finalize()
    
    digest2 = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest2.update(t)
    t_naught = digest2.finalize()
    t_naught = int.from_bytes(t+t_naught, byteorder='big') % ttp_n
    if(t_naught == pow(ttp_sig, ttp_e, ttp_n)):
        return True
    else:
        return False
    
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
    print("Client: s = <"+salt.hex()+">", flush=True)
    x = int.from_bytes(hashBytes(salt+upasswordbytes), byteorder='big')
    print("Client: x =",x, flush=True)
    #print("Client: I = \'"+uname+"\'", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        # Connect to TTP
        conn.connect(('127.0.4.18', 31802))
        conn.sendall(b'REQUEST KEY')
        ttp_n = int.from_bytes(conn.recv(128),byteorder='big')
        print("Client: TTP_N =", ttp_n, flush=True)
        ttp_e = int.from_bytes(conn.recv(128),byteorder='big')
        print("Client: TTP_e =", ttp_e)
        conn.close()
        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        #connect to server
        conn.connect((HOST, PORT))
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        print("Client: N =", N, flush=True)
        print("Client: g =", g, flush=True)
        
        a = genRand(N)
        print("Client: a =", a, flush=True)
        A = pow(g,a,N)
        print("Client: A =", A, flush=True)
        
        v = pow(g,x,N).to_bytes(64, byteorder='big')
        print("Client: v =",int.from_bytes(v, byteorder='big'), flush=True)
        conn.sendall(b'r')
        print("Client: Sending mode <"+bytes('r', 'utf-8').hex()+">", flush=True)
        conn.sendall(unamelength+unamebytes)
        print("Client: Sending len(username) <"+unamelength.hex()+">", flush=True)
        print("Client: Sending username <"+unamebytes.hex()+">", flush=True)
        conn.sendall(salt)
        print("Client: Sending salt <"+salt.hex()+">", flush=True)
        conn.sendall(v)
        print("Client: Sending v <"+v.hex()+">", flush=True)
        del x
        print("Client: Registration Successful", flush=True)
        conn.close()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST, PORT))
        N = int.from_bytes(conn.recv(64), byteorder='big')
        g = int.from_bytes(conn.recv(64), byteorder='big')
        conn.sendall(b'p')
        print("Client: Sending mode <"+bytes('p', 'utf-8').hex()+">", flush=True)
        conn.sendall(unamelength+unamebytes)
        print("Client: Sending len(username) <"+unamelength.hex()+">", flush=True)
        print("Client: Sending username <"+unamebytes.hex()+">", flush=True)
        servername_length = int.from_bytes(conn.recv(4), byteorder='big')
        print("Client: len(S) =",servername_length, flush=True)
        servername_bytes = conn.recv(servername_length)
        print("Client: S = \'"+servername_bytes.decode('utf-8')+"\'", flush=True)
        Server_N = conn.recv(128)
        print("Client: Server_N =",int.from_bytes(Server_N, byteorder='big'))
        Server_e = conn.recv(128)
        print("Client: Server_e =",int.from_bytes(Server_e, byteorder='big'))
        ttp_sig = int.from_bytes(conn.recv(128), byteorder='big')
        print("Client: TTP_SIG =", ttp_sig, flush=True)
        
        if (rsa_sig_verify(ttp_sig, ttp_e, ttp_n, servername_bytes, Server_N, Server_e) == False):
            exit(-1)
        else:
            print("Client: Server signature verified", flush=True)
        
        enc_A = rsa_encrypt(A, int.from_bytes(Server_e,byteorder='big'), int.from_bytes(Server_N, byteorder='big'))
        print("Client: Sending Enc(A) <"+enc_A.to_bytes(128, byteorder='big').hex()+">",flush=True)
        conn.sendall(enc_A.to_bytes(128, byteorder='big'))
        salt = conn.recv(16)
        print("Client: Client_s = <"+salt.hex()+">")
        B = int.from_bytes(conn.recv(64), byteorder='big')
        print("Client: B = ",B,flush=True)
        N_bytes = N.to_bytes(64, byteorder='big')
        g_bytes = g.to_bytes(64, byteorder='big')
        to_hash = N_bytes + g_bytes
        k = int.from_bytes(hashBytes(to_hash), byteorder='big')
        print("Client: k =",k,flush=True)
        x = int.from_bytes(hashBytes(salt+upasswordbytes), byteorder='big')
        u = int.from_bytes(hashBytes(A.to_bytes(64, byteorder='big') + B.to_bytes(64, byteorder='big')), byteorder='big') % N
        print("Client: u =",u,flush=True)
        k_client = pow((int.from_bytes(B.to_bytes(64, byteorder='big'), byteorder='big')%N) - ((k * int.from_bytes(v, byteorder='big'))%N), (a + (u*x)), N)
        print("Client: k_client =",k_client, flush=True)
        
        M_1 = hashBytes(A.to_bytes(64, byteorder='big') + B.to_bytes(64, byteorder='big') + k_client.to_bytes(64,byteorder='big'))
        print("Client: M1 = <"+M_1.hex()+">",flush=True)
        conn.sendall(M_1)
        print("Client: Sending M1 <"+M_1.hex()+">",flush=True)
        M_2 = hashBytes(A.to_bytes(64, byteorder='big') + M_1 + k_client.to_bytes(64, byteorder='big'))
        print("Client: M2 = <"+M_2.hex()+">",flush=True)
        if (M_2 == conn.recv(64)):
            print("Client: Negotiation successful", flush=True)
        else:
            print("Client: Negotiation unsuccessful", flush=True)
            exit(-1)
        
        fd = open(sys.argv[1], 'rb')
        byteArr = bytearray(fd.read())
        fd.close()
        
        extended_byteArr = byteArr + hashBytes(byteArr)
        #print(extended_byteArr)
        #key = keygen(k_client)
        key = hashBytes(k_client.to_bytes(64, byteorder='big'))
        iv = os.urandom(16)
        
        print("Client: iv = <"+iv.hex()+">",flush=True)
        print("Client: key =", key.hex(), flush=True)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bytes(extended_byteArr))
        padded_data += padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext =  encryptor.update(padded_data) + encryptor.finalize()
        
        forTransfer = iv + ciphertext
        
        size = len(forTransfer).to_bytes(4, byteorder='big')
        
        conn.sendall(size + forTransfer)
        print("Client: Sending len(PTXT) <"+size.hex()+">")
        print("Client: File "+sys.argv[1]+" sent.")
        
if __name__ == "__main__":
    main()
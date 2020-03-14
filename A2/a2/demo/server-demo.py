#!/usr/bin/env python3
import socket
import sys
import os
import sympy
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

def generatePrime():
    while True:
        while True:
            q = secrets.randbits(511)
            if sympy.isprime(q):
                break
        N = (2*q) + 1
        if sympy.isprime(N):
            return N

#leave for now, might need to optimize later
def calculatePrimRoots(num):
    for i in range(1, num, 1):
        if sympy.is_primitive_root(i, num):
            return i

def genRand(prime):
    upperBound = prime - 2
    return secrets.SystemRandom().randint(0, upperBound)
    
def hashBytes(bytesToHash):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytesToHash)
    return digest.finalize()

def main():
    saltDict = dict()
    vDict = dict()
    N = generatePrime()
    g = calculatePrimRoots(N)
    # socket.socket() creates a socket object
    # socket objects support the context manager type, this means we can use the 'with' statement
    # the two arguments to to socket() specify the address family and socket type:
    #   AF_INET is the internet address family for IPv4: indicates the
    #   SOCK_STREAM is the socket type ofr TCP, the protocol that will be used to transport messages on the network
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        # the bind function is used to associate the socket with a specific network interface
        # and port number.
        # Note that the arguments depend on the address family (here it is AF_INET, which expects a 2-tuple (host, port))
        # host can be a hostname, IP address (in the expcted format) or empty string.
        # the address here is the address for loopback interface -- this means only the host can connect
        # The port number must be between 1-65535
        s.bind((HOST, PORT))
        while True:
            print('Server listening...')

            # listen allows the server to accept connections.
            s.listen()

            # accept blocks and waits for an incoming connection. When a client connects,
            # it returns a new socket object representing the connection, and a tuple holding the client's address
            conn, addr = s.accept()

            ## conn is a new socket which is used to communicate with the client
            with conn:
                #print('Connected by', addr)
                print("Server: N =",N,flush=True)
                print("Server: g =",g,flush=True)
                print("Server: Sending N <"+N.to_bytes(64, byteorder='big').hex()+">",flush=True)
                print("Server: Sending g <"+g.to_bytes(64, byteorder='big').hex()+">",flush=True)
                publicBytes =  N.to_bytes(64, byteorder='big') + g.to_bytes(64, byteorder='big')
                conn.sendall(publicBytes)
                
                switch = conn.recv(1)
                switch = switch.decode('utf-8')
                
                length = int.from_bytes(conn.recv(4), byteorder='big')
                uname = conn.recv(length)
                user = uname.decode('utf-8')
                user = user.strip('\n')
                print("Server: I = "+user,flush=True)
                
                if switch == 'r':
                    salt = conn.recv(16)
                    print("Server: s = <"+salt.hex()+">",flush=True)
                    v = int.from_bytes(conn.recv(64), byteorder='big')
                    print("Server: v =",v,flush=True)
                    saltDict.update({user: salt})
                    vDict.update({user: v})
                    print("Server: Registration successful")
                
                if switch == 'p':
                    
                    
                    A = conn.recv(64)
                    salt = saltDict.get(user)
                    v = vDict.get(user)
                                    
                    k = int.from_bytes(hashBytes(N.to_bytes(64,byteorder='big') + g.to_bytes(64, byteorder='big')),\
                        byteorder='big')
                    
                    b = genRand(N)
                    B_int = (((k*v)%N) + pow(g,b,N))%N
                    B = B_int.to_bytes(64, byteorder='big')
                    
                    print("Server: b =",b,flush=True)
                    print("Server: k =",k,flush=True)
                    print("Server: B =",int.from_bytes(B, byteorder='big'),flush=True)
                    print("Server: I = "+user,flush=True)
                    print("Server: A =",int.from_bytes(A, byteorder='big'),flush=True)
                    
                    print("Server: Sending s <"+salt.hex()+">",flush=True)
                    conn.sendall(salt)
                    print("Server: Sending B <"+B.hex()+">",flush=True)
                    conn.sendall(B)
                    
                    u = int.from_bytes(hashBytes(A+B), byteorder='big') % N
                    print("Server: u =",u,flush=True)
                    
                    k_server = pow(((int.from_bytes(A, byteorder='big') % N) * pow(v,u,N)), b, N)                   
                    M_1 = hashBytes(A + B + k_server.to_bytes(64,byteorder='big'))
                    
                    print("Server: k_server =",k_server,flush=True)
                    print("Server: M1 = <"+M_1.hex()+">",flush=True)
                    
                    if (M_1 == conn.recv(64)):
                        M_2 = hashBytes(A + M_1 + k_server.to_bytes(64, byteorder='big'))
                        print("Server: M2 = <"+M_2.hex()+">",flush=True)
                        print("Server: Sending M2 <"+M_2.hex()+">",flush=True)
                        print("Server: Negotiation successful")
                        conn.sendall(M_2)
                    else:
                        conn.sendall(M_1)
                        print("Server: Negotiation unsucessful")
                    conn.close()

if __name__ == "__main__":
    main()
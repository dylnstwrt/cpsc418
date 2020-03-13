#!/usr/bin/env python3
import socket
import sys
import os
import sympy
import secrets

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
                print('Connected by', addr)
                
                publicBytes =  N.to_bytes(64, 'big') + g.to_bytes(64, 'big')
                conn.sendall(publicBytes)
                
                switch = conn.recv(1)
                switch = switch.decode('utf-8')
                
                length = int.from_bytes(conn.recv(4), 'big')
                uname = conn.recv(length)
                user = uname.decode('utf-8')
                user = user.strip('\n')
                
                if switch == 'r':
                    salt = conn.recv(16)
                    v = int.from_bytes(conn.recv(64), 'big')
                    saltDict.update({user: salt})
                    vDict.update({user: v})
                    print("Registration Successful")
                
                if switch == 'p':
                    
                    print(N)
                    print(g)
                    A = conn.recv(64)
                    salt = saltDict.get(user)
                    v = vDict.get(user)
                    
                    print(A)
                    
                    b = genRand(N)
                    B = pow(g, b, N).to_bytes(64, 'big')
                    print(B)
                    
                    conn.sendall(salt)
                    conn.sendall(B)
                    
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
                    
                    K_server = 
                    
                    M_1 = conn.recv(64)
                    
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(A + B + K_server)
                    toCompare = digest.finalize()
                    
                    if (toCompare == M_1):
                        print("MATCH")

if __name__ == "__main__":
    main()
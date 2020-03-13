#!/usr/bin/env python3
import socket
import sys
import os
import sympy
import secrets
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
    print('Server listening...')

    # listen allows the server to accept connections.
    s.listen()

    # accept blocks and waits for an incoming connection. When a client connects,
    # it returns a new socket object representing the connection, and a tuple holding the client's address
    conn, addr = s.accept()

    ## conn is a new socket which is used to communicate with the client
    with conn:
        print('Connected by', addr)

        # Note that we read the length first, then use the length to read the rest of the data
        # Some care needs to be taken when parsing data over sockets, this is one way to ensure
        # the data is parsed correctly if the size of the data is not known in advance.
        clientlength = int.from_bytes(conn.recv(4), 'big')
        uname = conn.recv(clientlength)
        user = uname.decode('utf-8')
        user = user.strip('\n')
        process_code = int.from_bytes(os.urandom(8), 'big')

        serverstring = "Thank you for contacting us " + user + ", your process ID is: " + str(process_code)
        sb = serverstring.encode('utf-8')
        conn.sendall(sb)

        print("Confirmation string sent, closing server")

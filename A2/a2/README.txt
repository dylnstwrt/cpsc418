'''
File: README.txt
Class: CPSC418 - Winter 2020
Name: Dylan Stewart
UCID: 30024193
Assignment : 2
Problem: 9
'''

RNG:
    - Random number generator used is randbits() from the python secrets module,
    which is described as a crypographically strong pseduo-random number generator
    suitable for managing secrets.
Prime Generation:
    - To generate a sophie-germaine prime, we continually generate a 511 bit
    random number (q) until we find one that is prime, then we perform the N = 2q + 1
    calculation.
    - To find a primitive root, we do a simple loop iterating through all values
    between 1 and the prime, and check if it is a primitive root.
Files:
    - Server.py
        - Server program. Will generate prime and a primitive root, wait for 
        connections, and depending on the switch character, will either register
        a user or negotiate with a user to get a shared key.
    - Client.py
        - Client program. Will prompt for username and password, connect to a 
        server, send the appropriate data required for registration, close
        it's connection and delete our x value, reconnect to the server, and send
        data indicating negotiation.
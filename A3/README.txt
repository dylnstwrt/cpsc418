File: README.txt
Class: CPSC418 - Winter 2020
Name: Dylan Stewart
UCID: 30024193
Assignment : 3
Problem: 8

a) Files Included:
    - TTP.py: Trusted third party in the file exchange. Communicates with both client and server.
    - Client.py: Establishes connection with TTP first, connects to server, registers, reconnects, and then executes
        authentication, key-exchange, message authentication, and finally bulk encryption.
    - Server.py: Establishes connection with TTP first, then listens for connection from client. Following a connection
        depending on the mode, the server will either register the users credentials, or begin the proceedure as aforemention.
    
b) Implemented:
    - All requirements are considered to be implemented, as per the autograder.

c) Not Implemented:
    - N/A
    
d) Bugs:
    - None known to the best of my knowledge.
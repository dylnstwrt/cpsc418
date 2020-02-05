import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Meta:
    def __init__(self, pt_filename, tp_filename, cs_password):
            self.pt_filename = pt_filename
            self.tp_filename = tp_filename
            self.cs_password = cs_password
    

def sha1_digest(byteArr):
    digest = hashes.Hash(hashes.SHA1(), backend = default_backend())
    digest.update(byteArr)
    return digest.finalize()

def keygen(password):
    long_key = sha1_digest(bytearray(password, "utf8"))
    key = bytearray(16)
    for i in range(16):
        key[i] = long_key[i]
    return key

def main():
    
    args = Meta(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]))
    fd = open(args.pt_filename)
    byteArr = bytearray(fd.read(), "utf8")
    fd.close()
    
    
    byteArr += sha1_digest(byteArr)
    
    key = keygen(args.cs_password)
    
    iv = os.urandom(16)
    output = open(args.tp_filename, "wb")
    # does this write to the file correctly
    output.write(iv)
    output.close()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

if __name__ == "__main__":
    main()
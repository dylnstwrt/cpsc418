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
    

def sha1_digest(toHash):
    digest = hashes.Hash(hashes.SHA1(), backend = default_backend())
    digest.update(toHash)
    val = digest.finalize()
    return val

def keygen(password):
    long_key = sha1_digest(bytearray(password, "utf8"))
    #long_key = sha1_digest(password)
    key = bytearray(16)
    for i in range(16):
        key[i] = long_key[i]
    return key

def main():
    
    args = Meta(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]))
    fd = open(args.pt_filename)

    byteArr = bytearray(fd.read(), "utf8")
    fd.close()

    extended_byteArr = byteArr + sha1_digest(byteArr)    
    key = keygen(args.cs_password)
    
    iv = os.urandom(16)
    output = open(args.tp_filename, "wb")
    # does this write to the file correctly
    output.write(iv)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(bytes(extended_byteArr))
    padded_data += padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    output.write(ciphertext)
    output.close()

if __name__ == "__main__":
    main()
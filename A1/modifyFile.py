import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



def calc_brute():
    brute = []
    for i in range(12):
        for j in range(31):
            toAdd = "1984"+"%02d" % (i+1) + "%02d" % (j+1)
            brute.append(toAdd)
    return brute
    
def keygen(password):

    digest = hashes.Hash(hashes.SHA1(), backend = default_backend())
    digest.update(bytes(password))
    hashed = digest.finalize()

    key = hashed[:16]

    return key


def main():

    fd = open(sys.argv[1], 'rb')
    cBytes = bytearray(fd.read())
    iv = cBytes[:16]
    ct = cBytes[16:]
    fd.close()
    
    brute = calc_brute()

    for password in brute:
        key = keygen(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(pad_data)
        data += unpadder.finalize()

        print(data)

        print(message)

if __name__ == "__main__":
    main()
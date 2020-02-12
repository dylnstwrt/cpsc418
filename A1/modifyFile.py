import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



def calc_brute():
    brute = []
    for k in range(1984,2021): #TODO Change this depending
        for i in range(12):
            for j in range(31):
                toAdd = "%4d" % k +"%02d" % (i+1) + "%02d" % (j+1) #TODO Change this back
                brute.append(toAdd)
    return brute
    
def keygen(password):

    digest = hashes.Hash(hashes.SHA1(), backend = default_backend())
    digest.update(bytes(password, "utf8"))
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
    possible_passwords = []

    for password in brute:
        key = keygen(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(plaintext)
        message
        try:
            message += unpadder.finalize()
        except:
            continue
        else:
            pass_pair = (password, message)
            possible_passwords.append(pass_pair)

    for i in range(len(possible_passwords)):
        if (str(possible_passwords[i][1]).find("FOXHOUND") != -1):
            correct_password = possible_passwords[i][0]
            message_bytes = possible_passwords[i][1]
            break
    
    try:
        print("\nPassword: "+correct_password+"\n")
    except:
        print("No password found within bounds")
        exit(-1)

    offset = len(message_bytes) - 20
    toDecode = message_bytes[:offset]
    toWrite = toDecode.decode('cp437')
    print("Original Message: "+toWrite)
    output = open("plain.txt", "w")
    output.write(toWrite)
    output.close()
    print("> plain.txt written")
    index = toWrite.find("CODE-RED")
    if(index != -1):
        toWrite = toWrite.replace("CODE-RED","CODE-BLUE", 10)
        print("Modified: "+toWrite)
        output = open("modifiedPlain.txt", "w")
        output.write(toWrite)
        output.close()
        print("> modifiedPlain.txt written")


if __name__ == "__main__":
    main()
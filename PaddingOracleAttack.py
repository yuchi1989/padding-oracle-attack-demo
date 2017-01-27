#!/usr/bin/python3
#from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto import Random
#from Crypto.Hash import HMAC

def pad(data):
    """
    PKCS#7 is described in RFC 5652
    """
    length = 16 - (len(data) % 16)
    data += (chr(length)*length).encode("ascii")
    return data

def unpad(data):
    data = data[:-(data[-1])]
    return data

class PaddingOracleAttack():
    def __init__(self):
        self.key = ""

    def aes_encrypt(self, plaintext, key):
        """
        AES256-CBC
        """
        self.key = key
        data = pad(plaintext.encode())
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        return init_vector + cipher.encrypt(data)

    def aes_decrypt(self, ciphertext, key):
        """
        AES256-CBC
        """
        self.key = key
        init_vector = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        data = cipher.decrypt(ciphertext)
        if not self.check_padding(data):
            return b""
        return unpad(data).decode()

    def check_padding(self, data):
        if data[-1] > AES.block_size or data[-1] <= 0:
            return False
        if data[-(data[-1]):] != ((chr(data[-1])*data[-1]).encode("ascii")):
            return False
        return True

    def padding_oracle(self, ciphertext):
        """
        return true if the decrypted ciphertext is padded correctly, otherwise return false
        """
        init_vector = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        data = cipher.decrypt(ciphertext)
        if not self.check_padding(data):
            return False
        else:
            return True

    def hack(self, ciphertext):
        """
        Decrypt ciphertext by calling padding_oracle
        """
        block = len(ciphertext)//16
        print(block)
        dtext = b''
        for i in range(block-1):
            dblock = b''
            for j in range(16):
                temp = bytearray(ciphertext[:16*(i+2)])
                for l in range(j):
                    temp[16*(i+1)-(l+1)] = temp[16*(i+1)-(l+1)] ^ (j+1) ^ dblock[-(l+1)]
                tempbyte = temp[16*(i+1)-(j+1)]
                hit = 0
                for k in range(255):
                    if k == j+1:
                        continue
                    temp[16*(i+1)-(j+1)] = tempbyte ^ (j+1) ^ k
                    r = self.padding_oracle(bytes(temp))
                    if r != False:
                        dblock = chr(k).encode("ascii") + dblock
                        hit = 1
                        break
                if hit == 0:
                    dblock = chr(j+1).encode("ascii") + dblock
                print(chr(dblock[0]), end=" ")
            dtext = dtext + dblock
            print("\n%s" % dtext.decode())
        dtext = dtext[:-(dtext[-1])]
        print("%s" % dtext.decode())
        return dtext.decode()




if __name__ == "__main__":

    from PaddingOracleAttack import PaddingOracleAttack
    p = PaddingOracleAttack()
    AES_KEY = "a"*32
    PLAINTEXT = "abcdefghijklmnopqrstuvwxyz"
    CIPHERTEXT = p.aes_encrypt(PLAINTEXT, AES_KEY)
    PLAINTEXT1 = p.aes_decrypt(CIPHERTEXT, AES_KEY)
    print(PLAINTEXT1)
    assert PLAINTEXT1 == PLAINTEXT
    PLAINTEXT2 = p.hack(CIPHERTEXT)
    print(PLAINTEXT2)
    assert PLAINTEXT2 == PLAINTEXT
    
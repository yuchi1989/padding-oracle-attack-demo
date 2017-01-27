# Padding Oracle Attack Demo

### Prerequisites
Python3
pip3
PyCrypto

### Installation instructions for ubuntu 14.04
sudo apt-get install python3
sudo apt-get install python3-pip
pip3 install pycrypto

### Example
```python
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

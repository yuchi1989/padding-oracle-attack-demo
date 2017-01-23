# Padding Oracle Attack Demo

### Example
```python
from PaddingOracleAttack import PaddingOracleAttack
p = PaddingOracleAttack()
key = "a"*32
c = p.AES_encrypt("abcdefghijklmnopqrstuvwxyz", key)
p.AES_decrypt(c, key)
p.hack(c)

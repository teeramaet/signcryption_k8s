import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

key = os.urandom(32)
iv = os.urandom(16)
print(base64.b64encode(key).decode("utf-8"))

print(base64.b64encode(iv).decode("utf-8"))
cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()

print(ct)
decryptor = cipher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize()
print(pt)

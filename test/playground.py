import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives import padding
import string

key = os.urandom(32)
iv = os.urandom(16)
print(base64.b64encode(key).decode("utf-8"))

print(base64.b64encode(iv).decode("utf-8"))
cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()

print(ct)
padder = padding.PKCS7(128).padder()
decryptor = cipher.decryptor()
padded_data = padder.update(ct)
padded_data += padder.finalize()
pt = decryptor.update(ct) + decryptor.finalize()
print(pt)


def remove_non_ascii(a_str):
    ascii_chars = set(string.printable)

    return "".join(filter(lambda x: x in ascii_chars, a_str))


printable = set(string.printable)
s = "QWRtaW4LCwsLCwsLCwsLC8BEhStZ6pIdM1qw8jdueOM=]"
s = base64.b64decode(s)
s = str(s)[2:-1]
print(remove_non_ascii(s))


separator = "\\"
result = s.split(separator, 1)[0]
print(result)  # 👉️ 'bobby'


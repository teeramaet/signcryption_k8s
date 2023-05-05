from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import json

yaml_file_b64 = base64.b64encode("iloveyou".encode("utf-8")).decode("utf-8")


private_key = ec.generate_private_key(ec.SECP384R1())
mutation_pub_key = private_key.public_key()
serialized_public = mutation_pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
mutation_pub_key_b64 = base64.b64encode(serialized_public).decode("utf-8")

signature = private_key.sign(yaml_file_b64.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
signature_b64 = base64.b64encode(signature).decode("utf-8")


signature2 = base64.b64decode(signature_b64.encode("utf-8"))
mutation_pub_key2 = base64.b64decode(mutation_pub_key_b64.encode("utf-8"))

mutation_pub_key2 = serialization.load_pem_public_key(
    mutation_pub_key2,
)

print(yaml_file_b64)
print("\n")

mutation_pub_key2.verify(
    signature2, yaml_file_b64.encode("utf-8"), ec.ECDSA(hashes.SHA256())
)

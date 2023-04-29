from fastapi import FastAPI, Body
import os
from os import environ
from models import Patch
import logging

import json
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

app = FastAPI()

# -----------------------Set log-----------------------
webhook = logging.getLogger(__name__)
uvicorn_logger = logging.getLogger("uvicorn")
uvicorn_logger.removeHandler(
    uvicorn_logger.handlers[0]
)  # Turn off uvicorn duplicate log
webhook.setLevel(logging.INFO)
logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s")


validation_pub_key = environ.get("VALIDATION_PUBLIC_KEY")
if not validation_pub_key:
    webhook.error(
        "The required environment variable 'VALIDATION_PUBLIC_KEY' isn't set."
    )
    exit(1)


# -----------------------Mutate-----------------------
# [{"op": "add", "path": "kubernetes.io/metadata/annotations/signature", "value": f"{signature}},{"op": "add", "path": "/spec/replicas", "value": 3}]
@app.post("/mutate")
def mutate_request(request: dict = Body(...)):
    patch_operations = []
    uid = request["request"]["uid"]
    object_in = request["request"]["object"]
    metadata = request["request"]["object"]["metadata"]
    kind = request["request"]["object"]["kind"]
    yaml_file_b64 = base64.b64encode(json.dumps(object_in))

    private_key = ec.generate_private_key(ec.SECP384R1())
    mutation_pub_key = private_key.public_key
    serialized_public = mutation_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    mutation_pub_key_b64 = base64.b64encode(serialized_public).decode("utf-8")
    shared_key = private_key.exchange(ec.ECDH(), validation_pub_key)
    signature = private_key.sign(yaml_file_b64, ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature).decode("utf-8")
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    webhook.info(
        f"Got '{signature}' as signature label, Got '{yaml_file_b64}' as yaml label, Got '{mutation_pub_key_b64}' as mutation_pub_key label, patching..."
    )

    # -----------------------Patch Secret-----------------------
    if "Secret" in kind:
        webhook.info(
            f"This is kubernetes secret file type. We will encrypt the data for confidentiality"
        )
        dict_data = kind["data"]

        for key, value in dict_data.items():
            dict_data[key] = encryptor.update(value) + encryptor.finalize()

        # -----------------------Encrypt-----------------------
        for key, value in dict_data.items():
            patch_operations.append(
                Patch(
                    op="replace",
                    path="/data",
                    value={f"{key}": f"{value}"},
                ).dict()
            )

    # -----------------------Patch yaml, signature, public_key, -----------------------
    patch_operations.append(
        Patch(
            op="add",
            path="/metadata/annotations",
            value={"digitalSignature": f"{signature_b64}"},
        ).dict()
    )

    patch_operations.append(
        Patch(
            op="add",
            path="/metadata/annotations",
            value={"yamlFile": f"{yaml_file_b64}"},
        ).dict()
    )

    patch_operations.append(
        Patch(
            op="add",
            path="/metadata/annotations",
            value={"publicKey": f"{mutation_pub_key_b64}"},
        ).dict()
    )

    patch = json.dumps(patch_operations).encode()
    webhook.info(f"Finish mutating...")
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,
            "patchType": "JSONPatch",
            "status": "Finish apply the mutation process",
            "patch": patch,
        },
    }

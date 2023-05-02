from fastapi import FastAPI, Body
import os
from os import environ
from models import Patch
import logging
import base64
import json
import cryptography

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding

app = FastAPI()

# -----------------------Set log-----------------------
webhook = logging.getLogger(__name__)
uvicorn_logger = logging.getLogger("uvicorn")
uvicorn_logger.removeHandler(
    uvicorn_logger.handlers[0]
)  # Turn off uvicorn duplicate log
webhook.setLevel(logging.INFO)
logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s")


validation_pub_key_b64 = environ.get("VALIDATION_PUBLIC_KEY")
if not validation_pub_key_b64:
    webhook.error(
        "The required environment variable 'VALIDATION_PUBLIC_KEY' isn't set."
    )
    exit(1)
validation_pub_key = base64.b64decode(validation_pub_key_b64.encode("utf-8"))


# -----------------------Mutate-----------------------
# [{"op": "add", "path": "kubernetes.io/metadata/annotations/signature", "value": f"{signature}},{"op": "add", "path": "/spec/replicas", "value": 3}]
@app.post("/mutate")
def mutate_request(request: dict = Body(...)):
    patch_operations = []
    uid = request["request"]["uid"]
    object_in = request["request"]["object"]
    kind = request["request"]["object"]["kind"]
    yaml_file_b64 = base64.b64encode(json.dumps(object_in).encode("utf-8")).decode(
        "utf-8"
    )

    private_key = ec.generate_private_key(ec.SECP384R1())
    mutation_pub_key = private_key.public_key()
    serialized_public = mutation_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    mutation_pub_key_b64 = base64.b64encode(serialized_public).decode("utf-8")
    loaded_public_key = serialization.load_pem_public_key(
        validation_pub_key,
    )
    shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)
    signature = private_key.sign(
        yaml_file_b64.encode("utf-8"), ec.ECDSA(hashes.SHA256())
    )
    signature_b64 = base64.b64encode(signature).decode("utf-8")
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)

    iv = os.urandom(16)
    iv_b64 = base64.b64encode(iv).decode("utf-8")
    patch_operations.append(
        Patch(
            op="add",
            path="/metadata/annotations/iv",
            value=f"{iv_b64}",
        ).dict()
    )

    webhook.info(f"Got '{signature_b64}' as signature label patching...")
    webhook.info(f"Got '{yaml_file_b64}' as yaml label patching...")
    webhook.info(
        f" Got '{mutation_pub_key_b64}' as mutation_pub_key label, patching..."
    )

    # -----------------------Patch Secret-----------------------
    if "Secret" in kind:
        for key, value in object_in["data"].items():
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            byte_value = value.encode("utf-8")
            padded_data = padder.update(byte_value)
            padded_data += padder.finalize()
            object_in["data"][key] = base64.b64encode(
                encryptor.update(padded_data) + encryptor.finalize()
            ).decode("utf-8")

        # -----------------------Encrypt-----------------------
        for key, value in object_in["data"].items():
            patch_operations.append(
                Patch(
                    op="replace",
                    path=f"/data/{key}",
                    value=f"{value}",
                ).dict()
            )

    # -----------------------Patch yaml, signature, public_key, -----------------------
    patch_operations.append(
        Patch(
            op="add",
            path="/metadata/annotations/digitalSignature",
            value=f"{signature_b64}",
        ).dict()
    )

    patch_operations.append(
        {
            "op": "add",
            "path": "/metadata/annotations/yamlFile",
            "value": f"{yaml_file_b64}",
        }
    )
    patch_operations.append(
        Patch(
            op="add",
            path="/metadata/annotations/mutate-pub-key",
            value=f"{mutation_pub_key_b64}",
        ).dict()
    )

    patch = base64.b64encode(json.dumps(patch_operations).encode("utf-8")).decode(
        "utf-8"
    )
    webhook.info(f"Finish mutating...")
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,
            "patchType": "JSONPatch",
            "status": {
                "message": "Finish apply the mutation process",
            },
            "patch": patch,
        },
    }


@app.post("/validate")
def validate_request(request: dict = Body(...)):
    uid = request["request"]["uid"]
    object_in = request["request"]["object"]
    kind = request["request"]["object"]["kind"]

    if object_in["metadata"]["annotations"]:
        if request["request"]["object"]["metadata"]["annotations"]["digitalSignature"]:
            signature_b64 = request["request"]["object"]["metadata"]["annotations"][
                "digitalSignature"
            ]
        else:
            return admission_response(
                False, uid, f"The digital Signature label aren't set!"
            )

        if request["request"]["object"]["metadata"]["annotations"]["yamlFile"]:
            yaml_file_b64 = request["request"]["object"]["metadata"]["annotations"][
                "yamlFile"
            ]
        else:
            return admission_response(False, uid, f"The label aren't set!")

        if request["request"]["object"]["metadata"]["annotations"]["mutate-pub-key"]:
            mutation_pub_key_b64 = request["request"]["object"]["metadata"][
                "annotations"
            ]["mutate-pub-key"]
        else:
            return admission_response(
                False, uid, f"The mutate-pub-key label aren't set!"
            )

        if request["request"]["object"]["metadata"]["annotations"]["iv"]:
            iv_b64 = request["request"]["object"]["metadata"]["annotations"]["iv"]
        else:
            return admission_response(False, uid, f"The iv label aren't set!")

        signature = base64.b64decode(signature_b64.encode("utf-8"))
        yaml_file = base64.b64decode(yaml_file_b64.encode("utf-8"))
        public_key = base64.b64decode(mutation_pub_key_b64.encode("utf-8"))
        iv = base64.b64decode(iv_b64.encode("utf-8"))

        try:
            public_key.verify(signature, yaml_file, ec.ECDSA(hashes.SHA256()))

        except:
            return admission_response(False, uid, f"Invalid signature !!! ...")
        else:
            return admission_response(True, uid, f"Integrity confirmed !!! ...")

    else:
        webhook.logger.error(
            f'Object {request["request"]["object"]["kind"]}/{request["request"]["object"]["metadata"]["name"]} doesn\'t have the required label. Request rejected!'
        )
        return admission_response(False, uid, f"The label aren't set!")


def admission_response(allowed, uid, message):
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {
                "message": f"{message}",
            },
        },
    }

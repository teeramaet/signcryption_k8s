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


app = FastAPI()

# -----------------------Set log-----------------------
webhook = logging.getLogger(__name__)
uvicorn_logger = logging.getLogger("uvicorn")
uvicorn_logger.removeHandler(
    uvicorn_logger.handlers[0]
)  # Turn off uvicorn duplicate log
webhook.setLevel(logging.INFO)
logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s")


# -----------------------Mutate-----------------------
@app.post("/validate")
def validate_request(request: dict = Body(...)):
    uid = request["request"]["uid"]
    object_in = request["request"]["object"]

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

        signature = base64.b64decode(signature_b64.encode("utf-8"))
        yaml_file = base64.b64decode(yaml_file_b64.encode("utf-8"))
        public_key = base64.b64decode(mutation_pub_key_b64.encode("utf-8"))

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

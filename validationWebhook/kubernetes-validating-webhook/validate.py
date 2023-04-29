from flask import Flask, request, jsonify
from os import environ
import logging
import base64
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

webhook = Flask(__name__)

webhook.config["LABEL"] = environ.get("LABEL")

webhook.logger.setLevel(logging.INFO)


@webhook.route("/validate", methods=["POST"])
def validating_webhook():
    request_info = request.get_json()
    uid = request_info["request"].get("uid")

    if request_info["request"]["object"]["metadata"]["annotations"].get():
        if request_info["request"]["object"]["metadata"]["annotations"][
            "digitalSignature_"
        ].get():
            signature_b64 = request_info["request"]["object"]["metadata"][
                "annotations"
            ]["digitalSignature_"].get()
        else:
            return admission_response(False, uid, f"The label aren't set!")

        if request_info["request"]["object"]["metadata"]["annotations"]["yamlFile"]:
            yaml_file_b64 = request_info["request"]["object"]["metadata"][
                "annotations"
            ]["yamlFile"]
        else:
            return admission_response(False, uid, f"The label aren't set!")

        if request_info["request"]["object"]["metadata"]["annotations"]["publicKeys"]:
            public_key_b64 = request_info["request"]["object"]["metadata"][
                "annotations"
            ]["publicKeys"]
        else:
            return admission_response(False, uid, f"The label aren't set!")

        signature = base64.b64decode(signature_b64.encode("utf-8"))
        yaml_file = base64.b64decode(yaml_file_b64.encode("utf-8"))
        public_key = base64.b64decode(public_key_b64.encode("utf-8"))
        try:
            public_key.verify(signature, yaml_file, ec.ECDSA(hashes.SHA256()))

        except:
            return admission_response(False, uid, f"Invalid signature !!! ...")
        else:
            return admission_response(True, uid, f"Integrity confirmed !!! ...")
    else:
        webhook.logger.error(
            f'Object {request_info["request"]["object"]["kind"]}/{request_info["request"]["object"]["metadata"]["name"]} doesn\'t have the required "{webhook.config["LABEL"]}" label. Request rejected!'
        )
        return admission_response(False, uid, f"The label aren't set!")


def admission_response(allowed, uid, message):
    return jsonify(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "allowed": allowed,
                "uid": uid,
                "status": {"message": message},
            },
        }
    )


if __name__ == "__main__":
    webhook.run(host="0.0.0.0", port=5000)

from flask import Flask, request, jsonify
import logging
import base64
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from os import environ
from cryptography.hazmat.primitives import serialization

webhook = Flask(__name__)


gunicorn_logger = logging.getLogger("gunicorn.error")
webhook.logger.handlers = gunicorn_logger.handlers
webhook.logger.setLevel(gunicorn_logger.level)


@webhook.route("/validate", methods=["POST"])
def validate_request():
    webhook.logger.info("hellos")
    req_data = request.get_json()
    uid = req_data["request"].get("uid")
    object_in = req_data["request"]["object"]

    if object_in["metadata"]["annotations"]:
        if req_data["request"]["object"]["metadata"]["annotations"].get(
            "digitalSignature"
        ):
            signature_b64 = req_data["request"]["object"]["metadata"][
                "annotations"
            ].get("digitalSignature")
        else:
            return admission_response(
                False, uid, f"The digital Signature label aren't set!"
            )

        if req_data["request"]["object"]["metadata"]["annotations"]["yamlFile"]:
            yaml_file_b64 = req_data["request"]["object"]["metadata"][
                "annotations"
            ].get("yamlFile")
        else:
            return admission_response(False, uid, f"The label aren't set!")

        if req_data["request"]["object"]["metadata"]["annotations"].get(
            "mutate-pub-key"
        ):
            mutation_pub_key_b64 = req_data["request"]["object"]["metadata"][
                "annotations"
            ].get("mutate-pub-key")
        else:
            return admission_response(
                False, uid, f"The mutate-pub-key label aren't set!"
            )

        signature = base64.b64decode(signature_b64.encode("utf-8"))
        yaml_file = yaml_file_b64.encode("utf-8")
        public_key_str = base64.b64decode(mutation_pub_key_b64.encode("utf-8"))
        public_key = serialization.load_pem_public_key(
            public_key_str,
        )

        try:
            public_key.verify(signature, yaml_file, ec.ECDSA(hashes.SHA256()))

        except:
            return admission_response(False, uid, f"Invalid signature !!! ...")
        else:
            return admission_response(True, uid, f"Integrity confirmed !!! ...")

    else:
        webhook.logger.error(
            f'Object {req_data["request"]["object"]["kind"]}/{req_data["request"]["object"]["metadata"]["name"]} doesn\'t have the required label. Request rejected!'
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


if __name__ == "__main__":
    webhook.run(host="0.0.0.0", port=5000)

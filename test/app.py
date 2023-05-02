from fastapi import FastAPI, Body
import os
from os import environ
from model import Patch
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

validation_pub_key_b64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUV6YnpsRFdhcUZEREJTUWJtOHpGWWpqbUVYbHdPM3JYUApuSzR0bmUwekpGdHJ0elN2SUY5Ty9MK0M5VFJ5UmJFWW5CTmpBeHd4K09FNG1YUHVrY3lXdlZvWktDYUNaaTZkCjdjSUpFODM5cW82TWkrbmFzU1VLRi9oUEY2OUt1SHBsCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
validation_pub_key = base64.b64decode(validation_pub_key_b64.encode("utf-8"))
request1 = {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "request": {
        "uid": "c68518d5-622d-4d36-8078-0bd087a22ae0",
        "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
        "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
        "requestKind": {"group": "apps", "version": "v1", "kind": "Deployment"},
        "requestResource": {
            "group": "apps",
            "version": "v1",
            "resource": "deployments",
        },
        "name": "nginx-deployment",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {
            "username": "minikube-user",
            "groups": ["system:masters", "system:authenticated"],
        },
        "object": {
            "kind": "Deployment",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "nginx-deployment",
                "namespace": "default",
                "creationTimestamp": None,
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{},"name":"nginx-deployment","namespace":"default"},"spec":{"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"image":"nginx:1.14.2","name":"nginx"}]}}}}\n'
                },
                "managedFields": [
                    {
                        "manager": "kubectl-client-side-apply",
                        "operation": "Update",
                        "apiVersion": "apps/v1",
                        "time": "2023-04-30T04:44:43Z",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:kubectl.kubernetes.io/last-applied-configuration": {},
                                }
                            },
                            "f:spec": {
                                "f:progressDeadlineSeconds": {},
                                "f:replicas": {},
                                "f:revisionHistoryLimit": {},
                                "f:selector": {},
                                "f:strategy": {
                                    "f:rollingUpdate": {
                                        ".": {},
                                        "f:maxSurge": {},
                                        "f:maxUnavailable": {},
                                    },
                                    "f:type": {},
                                },
                                "f:template": {
                                    "f:metadata": {"f:labels": {".": {}, "f:app": {}}},
                                    "f:spec": {
                                        "f:containers": {
                                            'k:{"name":"nginx"}': {
                                                ".": {},
                                                "f:image": {},
                                                "f:imagePullPolicy": {},
                                                "f:name": {},
                                                "f:resources": {},
                                                "f:terminationMessagePath": {},
                                                "f:terminationMessagePolicy": {},
                                            }
                                        },
                                        "f:dnsPolicy": {},
                                        "f:restartPolicy": {},
                                        "f:schedulerName": {},
                                        "f:securityContext": {},
                                        "f:terminationGracePeriodSeconds": {},
                                    },
                                },
                            },
                        },
                    }
                ],
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"creationTimestamp": None, "labels": {"app": "nginx"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "image": "nginx:1.14.2",
                                "resources": {},
                                "terminationMessagePath": "/dev/termination-log",
                                "terminationMessagePolicy": "File",
                                "imagePullPolicy": "IfNotPresent",
                            }
                        ],
                        "restartPolicy": "Always",
                        "terminationGracePeriodSeconds": 30,
                        "dnsPolicy": "ClusterFirst",
                        "securityContext": {},
                        "schedulerName": "default-scheduler",
                    },
                },
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {"maxUnavailable": "25%", "maxSurge": "25%"},
                },
                "revisionHistoryLimit": 10,
                "progressDeadlineSeconds": 600,
            },
            "status": {},
        },
        "oldObject": None,
        "dryRun": False,
        "options": {
            "kind": "CreateOptions",
            "apiVersion": "meta.k8s.io/v1",
            "fieldManager": "kubectl-client-side-apply",
            "fieldValidation": "Strict",
        },
    },
}

request2 = {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "request": {
        "uid": "b62dca8b-4c79-4a4f-9084-6f6d32709000",
        "kind": {"group": "", "version": "v1", "kind": "Secret"},
        "resource": {"group": "", "version": "v1", "resource": "secrets"},
        "requestKind": {"group": "", "version": "v1", "kind": "Secret"},
        "requestResource": {"group": "", "version": "v1", "resource": "secrets"},
        "name": "test1",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {
            "username": "minikube-user",
            "groups": ["system:masters", "system:authenticated"],
        },
        "object": {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": "test1",
                "namespace": "default",
                "creationTimestamp": None,
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"v1","data":{"webhook.crt":"dGVzdE1lc3NhZ2VQbGVhc2VJZ25vcmU=","webhook.key":"dGVzdE1lc3NhZ2VQbGVhc2VJZ25vcmUx"},"kind":"Secret","metadata":{"annotations":{"webhoook-enabled":"true"},"name":"test1","namespace":"default"},"type":"Opaque"}\n',
                    "webhoook-enabled": "true",
                },
                "managedFields": [
                    {
                        "manager": "kubectl-client-side-apply",
                        "operation": "Update",
                        "apiVersion": "v1",
                        "time": "2023-04-30T16:43:08Z",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:data": {
                                ".": {},
                                "f:webhook.crt": {},
                                "f:webhook.key": {},
                            },
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:kubectl.kubernetes.io/last-applied-configuration": {},
                                    "f:webhoook-enabled": {},
                                }
                            },
                            "f:type": {},
                        },
                    }
                ],
            },
            "data": {
                "webhook.crt": "dGVzdE1lc3NhZ2VQbGVhc2VJZ25vcmU=",
                "webhook.key": "dGVzdE1lc3NhZ2VQbGVhc2VJZ25vcmUx",
            },
            "type": "Opaque",
        },
        "oldObject": None,
        "dryRun": False,
        "options": {
            "kind": "CreateOptions",
            "apiVersion": "meta.k8s.io/v1",
            "fieldManager": "kubectl-client-side-apply",
            "fieldValidation": "Strict",
        },
    },
}
request = {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "request": {
        "uid": "3078c07c-9f36-49c9-9105-4909576683bf",
        "kind": {"group": "", "version": "v1", "kind": "Secret"},
        "resource": {"group": "", "version": "v1", "resource": "secrets"},
        "requestKind": {"group": "", "version": "v1", "kind": "Secret"},
        "requestResource": {"group": "", "version": "v1", "resource": "secrets"},
        "name": "test2",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {
            "username": "minikube-user",
            "groups": ["system:masters", "system:authenticated"],
        },
        "object": {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": "test2",
                "namespace": "default",
                "creationTimestamp": None,
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"v1","data":{"password":"UEBzc3cwcmQ=","username":"YWRtaW4="},"kind":"Secret","metadata":{"annotations":{"webhoook-enabled":"true"},"name":"test2","namespace":"default"},"type":"Opaque"}\n',
                    "webhoook-enabled": "true",
                },
                "managedFields": [
                    {
                        "manager": "kubectl-client-side-apply",
                        "operation": "Update",
                        "apiVersion": "v1",
                        "time": "2023-04-30T16:43:08Z",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:data": {".": {}, "f:password": {}, "f:username": {}},
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:kubectl.kubernetes.io/last-applied-configuration": {},
                                    "f:webhoook-enabled": {},
                                }
                            },
                            "f:type": {},
                        },
                    }
                ],
            },
            "data": {"password": "UEBzc3cwcmQ=", "username": "YWRtaW4="},
            "type": "Opaque",
        },
        "oldObject": None,
        "dryRun": False,
        "options": {
            "kind": "CreateOptions",
            "apiVersion": "meta.k8s.io/v1",
            "fieldManager": "kubectl-client-side-apply",
            "fieldValidation": "Strict",
        },
    },
}
request4 = {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "request": {
        "uid": "5379a92a-ea27-4510-86e1-c19db0076c03",
        "kind": {"group": "", "version": "v1", "kind": "Secret"},
        "resource": {"group": "", "version": "v1", "resource": "secrets"},
        "requestKind": {"group": "", "version": "v1", "kind": "Secret"},
        "requestResource": {"group": "", "version": "v1", "resource": "secrets"},
        "name": "test3",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {
            "username": "minikube-user",
            "groups": ["system:masters", "system:authenticated"],
        },
        "object": {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": "test3",
                "namespace": "default",
                "creationTimestamp": None,
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"v1","data":{"verySecret":"dG9wU2VjcmV0"},"kind":"Secret","metadata":{"annotations":{"webhoook-enabled":"true"},"name":"test3","namespace":"default"},"type":"Opaque"}\n',
                    "webhoook-enabled": "true",
                },
                "managedFields": [
                    {
                        "manager": "kubectl-client-side-apply",
                        "operation": "Update",
                        "apiVersion": "v1",
                        "time": "2023-04-30T16:43:08Z",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:data": {".": {}, "f:verySecret": {}},
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:kubectl.kubernetes.io/last-applied-configuration": {},
                                    "f:webhoook-enabled": {},
                                }
                            },
                            "f:type": {},
                        },
                    }
                ],
            },
            "data": {"verySecret": "dG9wU2VjcmV0"},
            "type": "Opaque",
        },
        "oldObject": None,
        "dryRun": False,
        "options": {
            "kind": "CreateOptions",
            "apiVersion": "meta.k8s.io/v1",
            "fieldManager": "kubectl-client-side-apply",
            "fieldValidation": "Strict",
        },
    },
}


patch_operations = []
uid = request["request"]["uid"]
object_in = request["request"]["object"]
kind = request["request"]["object"]["kind"]
yaml_file_b64 = base64.b64encode(json.dumps(object_in).encode("utf-8")).decode("utf-8")

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
signature = private_key.sign(yaml_file_b64.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
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
print(base64.b64encode(iv).decode("utf-8"))
# -----------------------Patch Secret-----------------------
if "Secret" in kind:
    for key, value in object_in["data"].items():
        print(key, value)
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


print("\n")
print("\n")
print(patch_operations)
[
    {
        "op": "add",
        "path": "/metadata/annotations/iv",
        "value": "5H/+ESuN6WI0L7EkImez0g==",
    },
    {"op": "replace", "path": "/data/password", "value": "Hzv2ok2tfL728D0RCaV3Zg=="},
    {"op": "replace", "path": "/data/username", "value": "vEoOBH83mNqAlWmqwJoFdw=="},
    {
        "op": "add",
        "path": "/metadata/annotations/digitalSignature",
        "value": "MGUCMQDTfYSahZnmZWFFa2FERogLGbOVXp9GpxmkzC9ezhxXtrl1fSSW5645ZXJIwcD1aXcCMGx7bo6AzoULqyskxVmsPtZNrPmxZoKG4JjxOazsqp+dsfI4NvULmLJR+MOS6NWGUA==",
    },
    {
        "op": "add",
        "path": "/metadata/annotations/yamlFile",
        "value": "eyJraW5kIjogIlNlY3JldCIsICJhcGlWZXJzaW9uIjogInYxIiwgIm1ldGFkYXRhIjogeyJuYW1lIjogInRlc3QyIiwgIm5hbWVzcGFjZSI6ICJkZWZhdWx0IiwgImNyZWF0aW9uVGltZXN0YW1wIjogbnVsbCwgImFubm90YXRpb25zIjogeyJrdWJlY3RsLmt1YmVybmV0ZXMuaW8vbGFzdC1hcHBsaWVkLWNvbmZpZ3VyYXRpb24iOiAie1wiYXBpVmVyc2lvblwiOlwidjFcIixcImRhdGFcIjp7XCJwYXNzd29yZFwiOlwiVUVCemMzY3djbVE9XCIsXCJ1c2VybmFtZVwiOlwiWVdSdGFXND1cIn0sXCJraW5kXCI6XCJTZWNyZXRcIixcIm1ldGFkYXRhXCI6e1wiYW5ub3RhdGlvbnNcIjp7XCJ3ZWJob29vay1lbmFibGVkXCI6XCJ0cnVlXCJ9LFwibmFtZVwiOlwidGVzdDJcIixcIm5hbWVzcGFjZVwiOlwiZGVmYXVsdFwifSxcInR5cGVcIjpcIk9wYXF1ZVwifVxuIiwgIndlYmhvb29rLWVuYWJsZWQiOiAidHJ1ZSJ9LCAibWFuYWdlZEZpZWxkcyI6IFt7Im1hbmFnZXIiOiAia3ViZWN0bC1jbGllbnQtc2lkZS1hcHBseSIsICJvcGVyYXRpb24iOiAiVXBkYXRlIiwgImFwaVZlcnNpb24iOiAidjEiLCAidGltZSI6ICIyMDIzLTA0LTMwVDE2OjQzOjA4WiIsICJmaWVsZHNUeXBlIjogIkZpZWxkc1YxIiwgImZpZWxkc1YxIjogeyJmOmRhdGEiOiB7Ii4iOiB7fSwgImY6cGFzc3dvcmQiOiB7fSwgImY6dXNlcm5hbWUiOiB7fX0sICJmOm1ldGFkYXRhIjogeyJmOmFubm90YXRpb25zIjogeyIuIjoge30sICJmOmt1YmVjdGwua3ViZXJuZXRlcy5pby9sYXN0LWFwcGxpZWQtY29uZmlndXJhdGlvbiI6IHt9LCAiZjp3ZWJob29vay1lbmFibGVkIjoge319fSwgImY6dHlwZSI6IHt9fX1dfSwgImRhdGEiOiB7InBhc3N3b3JkIjogIlVFQnpjM2N3Y21RPSIsICJ1c2VybmFtZSI6ICJZV1J0YVc0PSJ9LCAidHlwZSI6ICJPcGFxdWUifQ==",
    },
    {
        "op": "add",
        "path": "/metadata/annotations/mutate-pub-key",
        "value": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUV4L29KVVkyQmdQWUlpQi9KRUlkS0UrdU5ta1BGY3VqWAp1dGtuZ3R1WjRzZ3dZRmhyalNyZTVTS3JnQ2p1QU9tK1pkb3VFTWlmaFFlbTJNbHM3QzhnL0d6aWVDYzcwbW9KCm5xRUFWd3RlcEdjN085amVIK3VQamVlTjZMM01UV2hRCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
    },
]
"""
@app.post("/mutate")
def mutate_request(request: dict = Body(...)):
    webhook.info(f"Applying nodeSelector for {request}.")
    uid = request["request"]["uid"]
    # selector = request["request"]["object"]["spec"]["template"]["spec"]
    # object_in = request["request"]["object"]

    return admission_review(
        uid,
        "Successfully added nodeSelector.",
        True if "nodeSelector" in request else False,
    )

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
        public_key = base64.b64decode(public_key_b64.encode("utf-8"))
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











[
    {
        "op": "add",
        "path": "/metadata/annotations",
        "value": [{
            "digitalSignature": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUUrRnRlaDJxdUo5WmE2OTgrMm9UemxwOHZDajdza2J1Wgo3RW00b2M4NlZ4RVpGd2ZOUEdRNkZQNVhMbkQrNUdQNGkxZTRLTk11WmxSUmpEc0k3WTRiL0hYREhMSmNDb0x6CnBxWjdxdkh1MFpyMzJaRXVGdEZrNjdTUlRvdExKdzZ5Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
        },
    }],
    {
        "op": "add",
        "path": "/metadata/annotations",
        "value": {
            "yamlFile": "eyJraW5kIjogIkRlcGxveW1lbnQiLCAiYXBpVmVyc2lvbiI6ICJhcHBzL3YxIiwgIm1ldGFkYXRhIjogeyJuYW1lIjogIm5naW54LWRlcGxveW1lbnQiLCAibmFtZXNwYWNlIjogImRlZmF1bHQiLCAiY3JlYXRpb25UaW1lc3RhbXAiOiBudWxsLCAiYW5ub3RhdGlvbnMiOiB7Imt1YmVjdGwua3ViZXJuZXRlcy5pby9sYXN0LWFwcGxpZWQtY29uZmlndXJhdGlvbiI6ICJ7XCJhcGlWZXJzaW9uXCI6XCJhcHBzL3YxXCIsXCJraW5kXCI6XCJEZXBsb3ltZW50XCIsXCJtZXRhZGF0YVwiOntcImFubm90YXRpb25zXCI6e30sXCJuYW1lXCI6XCJuZ2lueC1kZXBsb3ltZW50XCIsXCJuYW1lc3BhY2VcIjpcImRlZmF1bHRcIn0sXCJzcGVjXCI6e1wic2VsZWN0b3JcIjp7XCJtYXRjaExhYmVsc1wiOntcImFwcFwiOlwibmdpbnhcIn19LFwidGVtcGxhdGVcIjp7XCJtZXRhZGF0YVwiOntcImxhYmVsc1wiOntcImFwcFwiOlwibmdpbnhcIn19LFwic3BlY1wiOntcImNvbnRhaW5lcnNcIjpbe1wiaW1hZ2VcIjpcIm5naW54OjEuMTQuMlwiLFwibmFtZVwiOlwibmdpbnhcIn1dfX19fVxuIn0sICJtYW5hZ2VkRmllbGRzIjogW3sibWFuYWdlciI6ICJrdWJlY3RsLWNsaWVudC1zaWRlLWFwcGx5IiwgIm9wZXJhdGlvbiI6ICJVcGRhdGUiLCAiYXBpVmVyc2lvbiI6ICJhcHBzL3YxIiwgInRpbWUiOiAiMjAyMy0wNC0zMFQwNDo0NDo0M1oiLCAiZmllbGRzVHlwZSI6ICJGaWVsZHNWMSIsICJmaWVsZHNWMSI6IHsiZjptZXRhZGF0YSI6IHsiZjphbm5vdGF0aW9ucyI6IHsiLiI6IHt9LCAiZjprdWJlY3RsLmt1YmVybmV0ZXMuaW8vbGFzdC1hcHBsaWVkLWNvbmZpZ3VyYXRpb24iOiB7fX19LCAiZjpzcGVjIjogeyJmOnByb2dyZXNzRGVhZGxpbmVTZWNvbmRzIjoge30sICJmOnJlcGxpY2FzIjoge30sICJmOnJldmlzaW9uSGlzdG9yeUxpbWl0Ijoge30sICJmOnNlbGVjdG9yIjoge30sICJmOnN0cmF0ZWd5IjogeyJmOnJvbGxpbmdVcGRhdGUiOiB7Ii4iOiB7fSwgImY6bWF4U3VyZ2UiOiB7fSwgImY6bWF4VW5hdmFpbGFibGUiOiB7fX0sICJmOnR5cGUiOiB7fX0sICJmOnRlbXBsYXRlIjogeyJmOm1ldGFkYXRhIjogeyJmOmxhYmVscyI6IHsiLiI6IHt9LCAiZjphcHAiOiB7fX19LCAiZjpzcGVjIjogeyJmOmNvbnRhaW5lcnMiOiB7Ims6e1wibmFtZVwiOlwibmdpbnhcIn0iOiB7Ii4iOiB7fSwgImY6aW1hZ2UiOiB7fSwgImY6aW1hZ2VQdWxsUG9saWN5Ijoge30sICJmOm5hbWUiOiB7fSwgImY6cmVzb3VyY2VzIjoge30sICJmOnRlcm1pbmF0aW9uTWVzc2FnZVBhdGgiOiB7fSwgImY6dGVybWluYXRpb25NZXNzYWdlUG9saWN5Ijoge319fSwgImY6ZG5zUG9saWN5Ijoge30sICJmOnJlc3RhcnRQb2xpY3kiOiB7fSwgImY6c2NoZWR1bGVyTmFtZSI6IHt9LCAiZjpzZWN1cml0eUNvbnRleHQiOiB7fSwgImY6dGVybWluYXRpb25HcmFjZVBlcmlvZFNlY29uZHMiOiB7fX19fX19XX0sICJzcGVjIjogeyJyZXBsaWNhcyI6IDEsICJzZWxlY3RvciI6IHsibWF0Y2hMYWJlbHMiOiB7ImFwcCI6ICJuZ2lueCJ9fSwgInRlbXBsYXRlIjogeyJtZXRhZGF0YSI6IHsiY3JlYXRpb25UaW1lc3RhbXAiOiBudWxsLCAibGFiZWxzIjogeyJhcHAiOiAibmdpbngifX0sICJzcGVjIjogeyJjb250YWluZXJzIjogW3sibmFtZSI6ICJuZ2lueCIsICJpbWFnZSI6ICJuZ2lueDoxLjE0LjIiLCAicmVzb3VyY2VzIjoge30sICJ0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjogIi9kZXYvdGVybWluYXRpb24tbG9nIiwgInRlcm1pbmF0aW9uTWVzc2FnZVBvbGljeSI6ICJGaWxlIiwgImltYWdlUHVsbFBvbGljeSI6ICJJZk5vdFByZXNlbnQifV0sICJyZXN0YXJ0UG9saWN5IjogIkFsd2F5cyIsICJ0ZXJtaW5hdGlvbkdyYWNlUGVyaW9kU2Vjb25kcyI6IDMwLCAiZG5zUG9saWN5IjogIkNsdXN0ZXJGaXJzdCIsICJzZWN1cml0eUNvbnRleHQiOiB7fSwgInNjaGVkdWxlck5hbWUiOiAiZGVmYXVsdC1zY2hlZHVsZXIifX0sICJzdHJhdGVneSI6IHsidHlwZSI6ICJSb2xsaW5nVXBkYXRlIiwgInJvbGxpbmdVcGRhdGUiOiB7Im1heFVuYXZhaWxhYmxlIjogIjI1JSIsICJtYXhTdXJnZSI6ICIyNSUifX0sICJyZXZpc2lvbkhpc3RvcnlMaW1pdCI6IDEwLCAicHJvZ3Jlc3NEZWFkbGluZVNlY29uZHMiOiA2MDB9LCAic3RhdHVzIjoge319"
        },
    },
    {
        "op": "add",
        "path": "/metadata/annotations",
        "value": {
            "publicKey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUUrRnRlaDJxdUo5WmE2OTgrMm9UemxwOHZDajdza2J1Wgo3RW00b2M4NlZ4RVpGd2ZOUEdRNkZQNVhMbkQrNUdQNGkxZTRLTk11WmxSUmpEc0k3WTRiL0hYREhMSmNDb0x6CnBxWjdxdkh1MFpyMzJaRXVGdEZrNjdTUlRvdExKdzZ5Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
        },
    },
]

print(
    {
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
)
"""


{
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "request": {
        "uid": "c68518d5-622d-4d36-8078-0bd087a22ae0",
        "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
        "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
        "requestKind": {"group": "apps", "version": "v1", "kind": "Deployment"},
        "requestResource": {
            "group": "apps",
            "version": "v1",
            "resource": "deployments",
        },
        "name": "nginx-deployment",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {
            "username": "minikube-user",
            "groups": ["system:masters", "system:authenticated"],
        },
        "object": {
            "kind": "Deployment",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "nginx-deployment",
                "namespace": "default",
                "creationTimestamp": None,
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{},"name":"nginx-deployment","namespace":"default"},"spec":{"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"image":"nginx:1.14.2","name":"nginx"}]}}}}\n'
                },
                "managedFields": [
                    {
                        "manager": "kubectl-client-side-apply",
                        "operation": "Update",
                        "apiVersion": "apps/v1",
                        "time": "2023-04-30T04:44:43Z",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:kubectl.kubernetes.io/last-applied-configuration": {},
                                }
                            },
                            "f:spec": {
                                "f:progressDeadlineSeconds": {},
                                "f:replicas": {},
                                "f:revisionHistoryLimit": {},
                                "f:selector": {},
                                "f:strategy": {
                                    "f:rollingUpdate": {
                                        ".": {},
                                        "f:maxSurge": {},
                                        "f:maxUnavailable": {},
                                    },
                                    "f:type": {},
                                },
                                "f:template": {
                                    "f:metadata": {"f:labels": {".": {}, "f:app": {}}},
                                    "f:spec": {
                                        "f:containers": {
                                            'k:{"name":"nginx"}': {
                                                ".": {},
                                                "f:image": {},
                                                "f:imagePullPolicy": {},
                                                "f:name": {},
                                                "f:resources": {},
                                                "f:terminationMessagePath": {},
                                                "f:terminationMessagePolicy": {},
                                            }
                                        },
                                        "f:dnsPolicy": {},
                                        "f:restartPolicy": {},
                                        "f:schedulerName": {},
                                        "f:securityContext": {},
                                        "f:terminationGracePeriodSeconds": {},
                                    },
                                },
                            },
                        },
                    }
                ],
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "nginx"}},
                "template": {
                    "metadata": {"creationTimestamp": None, "labels": {"app": "nginx"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "image": "nginx:1.14.2",
                                "resources": {},
                                "terminationMessagePath": "/dev/termination-log",
                                "terminationMessagePolicy": "File",
                                "imagePullPolicy": "IfNotPresent",
                            }
                        ],
                        "restartPolicy": "Always",
                        "terminationGracePeriodSeconds": 30,
                        "dnsPolicy": "ClusterFirst",
                        "securityContext": {},
                        "schedulerName": "default-scheduler",
                    },
                },
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {"maxUnavailable": "25%", "maxSurge": "25%"},
                },
                "revisionHistoryLimit": 10,
                "progressDeadlineSeconds": 600,
            },
            "status": {},
        },
        "oldObject": None,
        "dryRun": False,
        "options": {
            "kind": "CreateOptions",
            "apiVersion": "meta.k8s.io/v1",
            "fieldManager": "kubectl-client-side-apply",
            "fieldValidation": "Strict",
        },
    },
}

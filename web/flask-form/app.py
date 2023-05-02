from flask import Flask, render_template, request
from forms import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

app = Flask(__name__)
app.secret_key = "development key"
symmetric_key_b64 = "SPeADfNUHZW+1MBzSjNVXHbX7E+aF5aYxwOInz5bL5Q="
iv_b64 = "8n7XEa+7UhPzWnkAg0qMRg=="

symmetric_key = base64.b64decode(symmetric_key_b64.encode("utf-8"))
iv = base64.b64decode(iv_b64.encode("utf-8"))


@app.route("/", methods=["GET", "POST"])
def hello():
    form = Base64_Encrypt_Form()

    if request.method == "POST":
        if form.validate() == False:
            return render_template("index.html", form=form)
        else:
            input_data = form.name.data
            cipher = Cipher(algorithms.AES256(symmetric_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            data_byte = input_data.encode("utf-8")
            padded_data = padder.update(data_byte)
            padded_data += padder.finalize()
            cypher_text = encryptor.update(padded_data) + encryptor.finalize()
            cypher_text_b64 = base64.b64encode(cypher_text).decode("utf-8")
            return render_template(
                "registro.html", name=input_data, last_name=cypher_text_b64
            )
    elif request.method == "GET":
        return render_template("index.html", form=form)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="8080")

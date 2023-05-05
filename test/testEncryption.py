import base64


def show_original_message(s):
    s = base64.b64decode(s)
    s = str(s)[2:-1]
    separator = "\\"
    return s.split(separator, 1)[0]


if __name__ == "__main__":
    # -----------------------Check if the encryption and decryption process successfully -----------------------
    base64_decrypt_string = "YWNlc3Njb250cm9sBAQEBGvlodA50fjatZ9pRZKFbUM="

    print(show_original_message(base64_decrypt_string))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def GCM_decrypt(encrypt_data, key, iv):
    aesgcm = AESGCM(key)
    plain_data = aesgcm.decrypt(iv, encrypt_data, None)
    return plain_data

with open("rsa_priv.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open('./IV',  "rb") as file_object:
    iv = file_object.read()

with open('./EKEK',  "rb") as file_object:
    ekek = file_object.read()
    kek = rsa_decrypt(ekek, private_key)
with open('./EKEK.de',  "wb") as file_object:
    file_object.write(kek)

with open('./ESECRET',  "rb") as file_object:
    esecret = file_object.read()
    plain_data = GCM_decrypt(esecret, kek, iv)
with open('./ESECRET.de',  "wb") as file_object:
    file_object.write(plain_data)

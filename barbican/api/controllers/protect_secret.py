from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from base64 import b64encode
from oslo_serialization import base64

from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1
from OpenSSL.crypto import load_privatekey, dump_privatekey

from Crypto.Util.asn1 import DerSequence, DerOctetString, DerInteger
from Crypto.Util.number import long_to_bytes, bytes_to_long

from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der.encoder import encode


def _invalid_content_type():
    pecan.abort(400, u._('Invalid content_type'))

def gcm_encrypt(data, key, iv, content_type, content_encoding):
    if content_type != 'application/octet-stream':
        _invalid_content_type()

    if content_encoding:
        if content_encoding.lower() == 'base64':
            data = base64.decode_as_bytes(data)

    aesgcm = AESGCM(key)
    encrypt_data = aesgcm.encrypt(iv, data, None)

    if content_encoding:
        if content_encoding.lower() == 'base64':
            encrypt_data = base64.encode_as_bytes(encrypt_data)

    return encrypt_data

def kpt_encrypt_rsa_field(data, key, iv):
    data = long_to_bytes(data)
    aesgcm = AESGCM(key)
    encrypt_data = aesgcm.encrypt(iv, data, None)
    encrypt_data = encrypt_data[:-4]
    return bytes_to_long(encrypt_data)

def kpt_encrypt(data, key, iv, content_type, content_encoding):
    if content_type != 'application/octet-stream':
        _invalid_content_type()

    if content_encoding:
        if content_encoding.lower() == 'base64':
            data = base64.decode_as_bytes(data)

    rsa_priv = load_privatekey(FILETYPE_PEM, data)
    rsa_priv_der = DerSequence()
    rsa_priv_der.decode(dump_privatekey(FILETYPE_ASN1, rsa_priv))
    rsa_priv_der[3] = kpt_encrypt_rsa_field(rsa_priv_der[3], key, iv)
    rsa_priv_der[4] = kpt_encrypt_rsa_field(rsa_priv_der[4], key, iv)
    rsa_priv_der[5] = kpt_encrypt_rsa_field(rsa_priv_der[5], key, iv)
    rsa_priv_der[6] = kpt_encrypt_rsa_field(rsa_priv_der[6], key, iv)
    rsa_priv_der[7] = kpt_encrypt_rsa_field(rsa_priv_der[7], key, iv)
    rsa_priv_der[8] = kpt_encrypt_rsa_field(rsa_priv_der[8], key, iv)
    wrapped_rsa_priv_der = rsa_priv_der.encode()

    enc_algo_id = encode(ObjectIdentifier('2.16.840.1.101.3.4.1.6'))
    iv = DerOctetString(value=iv).encode()
    ic = DerInteger(0x01).encode()
    hmac_algo_id = encode(ObjectIdentifier('1.2.840.113549.2.7'))

    ENC_ALGO_DESP = DerSequence()
    ENC_ALGO_DESP.append(enc_algo_id)
    ENC_ALGO_DESP.append(iv)
    ENC_ALGO_DESP.append(ic)
    ENC_ALGO_DESP.append(hmac_algo_id)

    wrapping_format = encode(ObjectIdentifier('1.2.840.113549.1.5.15'))
    encrypt_algo = ENC_ALGO_DESP.encode()

    WRAP_DESP = DerSequence()
    WRAP_DESP.append(wrapping_format)
    WRAP_DESP.append(encrypt_algo)

    version = DerInteger(0x01).encode()
    algo_id = encode(ObjectIdentifier('1.2.840.113549.1.1.5'))
    wrapped_key = DerOctetString(value=wrapped_rsa_priv_der).encode()

    WRAPPED_PRIV_KEY = DerSequence()
    WRAPPED_PRIV_KEY.append(version)
    WRAPPED_PRIV_KEY.append(algo_id)
    WRAPPED_PRIV_KEY.append(wrapped_key)

    wrap_desp = WRAP_DESP.encode()
    encrypted_data = WRAPPED_PRIV_KEY.encode()

    wpinfo = DerSequence()
    wpinfo.append(wrap_desp)
    wpinfo.append(encrypted_data)

    wpk = b64encode(wpinfo.encode())

    spilt_wpk= '\n'.join(wpk[i:i+64] for i in range(0, len(wpk), 64))
    encrypt_data = '-----BEGIN WRAPPED PRIVATE KEY-----\n' + spilt_wpk + '\n' + '-----END WRAPPED PRIVATE KEY-----\n'

    if content_encoding:
        if content_encoding.lower() == 'base64':
            encrypt_data = base64.encode_as_bytes(encrypt_data)

    return encrypt_data

def rsa_pub_encrypt(data, pub):
    rsa_pub = load_pem_public_key(pub, backend=default_backend())
    encrypt_data = rsa_pub.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None))

    return encrypt_data

# the same as rsa_pub_encrypt for demo
def tpm_rsa_duplication(data, pub):
    rsa_pub = load_pem_public_key(pub, backend=default_backend())
    encrypt_data = rsa_pub.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None))

    return encrypt_data
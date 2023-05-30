from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

from fastapi import FastAPI

app = FastAPI()


def encrypt_with_rsa(data):
    public_key_path = 'public_key.pem'
    # Load the public key from the given file path
    with open(public_key_path, 'rb') as key_file:
        pem_data = key_file.read()
        public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())

    cipher = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encoded_data = base64.b64encode(cipher).decode('utf-8')
    return encoded_data


def encrypt_by_symmetric_key(json_data, decrypted_sek):
    sek_byte = base64.b64decode(decrypted_sek)
    aes_key = Cipher(algorithms.AES(sek_byte), modes.ECB(), backend=default_backend()).encryptor()
    try:
        padded_data = sym_padding.pad(json_data.encode(), algorithms.AES.block_size)
        encrypted_bytes = aes_key.update(padded_data) + aes_key.finalize()
        encrypted_json = base64.b64encode(encrypted_bytes).decode()
        return encrypted_json
    except Exception as e:
        return f"Exception {e}"


def decrypt_sek_with_appkey(encrypted_sek, base64_appkey):
    appkey = base64.b64decode(base64_appkey)
    encrypted_sek = base64.b64decode(encrypted_sek)
    cipher = Cipher(algorithms.AES(appkey), modes.ECB(), backend=default_backend()).decryptor()
    decrypted_sek = cipher.update(encrypted_sek) + cipher.finalize()
    unpadded_sek = sym_padding.unpad(decrypted_sek, algorithms.AES.block_size)
    base64_decoded_sek = base64.b64encode(unpadded_sek).decode('utf-8')
    return base64_decoded_sek


@app.post('/encryptrsa')
async def encrypt_route_rsa(request: Request):
    data = await request.json()
    data = data['data']
    encoded_data = encrypt_with_rsa(data)
    return {'encrypted_data': encoded_data}


@app.post('/encryptaes')
async def encrypt_route(request: Request):
    data = await request.json()
    data = data['data']
    appkey = data['appkey']
    encrypted_Data = encrypt_by_symmetric_key(data, appkey)
    return {'encrypted_Data': encrypted_Data}


@app.post('/decryptsek')
async def decrypt_route(request: Request):
    data = await request.json()
    encrypted_sek = data['encrypted_sek']
    appkey = data['appkey']
    decrypted_sek = decrypt_sek_with_appkey(encrypted_sek, appkey)
    return {'decrypted_sek': decrypted_sek}

    

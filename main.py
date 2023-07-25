from fastapi import FastAPI, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi import HTTPException
from PIL import Image
import qrcode
import barcode
from barcode.writer import ImageWriter
import fitz as fit
from io import BytesIO
import shutil
import json
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = FastAPI()


def encrypt_with_rsa(data):
  public_key_path = 'public_key.pem'
  # Load the public key from the given file path
  with open(public_key_path, 'rb') as key_file:
    pem_data = key_file.read()
    public_key = RSA.import_key(pem_data)

  cipher = PKCS1_v1_5.new(public_key)
  encrypted_data = cipher.encrypt(data.encode('utf-8'))
  encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
  return encoded_data


def encrypt_by_symmetric_key(json_data, decrypted_sek):
  #json_data = json.dumps(json_data)
  sek_byte = base64.b64decode(decrypted_sek)
  aes_key = AES.new(sek_byte, AES.MODE_ECB)
  try:
    padded_data = pad(json_data.encode(), AES.block_size)
    encrypted_bytes = aes_key.encrypt(padded_data)
    encrypted_json = base64.b64encode(encrypted_bytes).decode()
    return encrypted_json
  except Exception as e:
    return f"Exception {e}"


def decrypt_sek_with_appkey(encrypted_sek, base64_appkey):
  appkey = base64.b64decode(base64_appkey)
  encrypted_sek = base64.b64decode(encrypted_sek)
  cipher = AES.new(appkey, AES.MODE_ECB)
  decrypted_sek = cipher.decrypt(encrypted_sek)
  print(decrypted_sek)
  unpadded_sek = unpad(decrypted_sek, AES.block_size)
  print(unpadded_sek)
  base64_decoded_sek = base64.b64encode(unpadded_sek).decode('utf-8')
  return base64_decoded_sek




# Default root endpoint
@app.get("/")
async def root():
  return {"message": "Hello world"}

@app.get("/generate_qr")
def generate_qr(QRdata: str):
    qr = qrcode.QRCode(
        version=None,  # Set version to None for automatic sizing
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=0,
    )
    qr.add_data(QRdata)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_image = qr_image.resize((136, 136))
    
    # Create an in-memory buffer to store the image data
    img_buffer = io.BytesIO()
    qr_image.save(img_buffer, format="PNG")
    img_buffer.seek(0)
    
    return {
        "file": img_buffer,
        "filename": "qr_code.png"
    }
  
  
# Example path parameter
@app.get("/name/{name}")
async def name(name: str):
  return {"message": f"Hello {name}"}


@app.post('/encryptrsa')
async def encrypt_route_rsa(request: Request):
  data = await request.json()
  data = data['data']
  encoded_data = encrypt_with_rsa(data)
  return {'encrypted_data': encoded_data}


@app.post('/encryptaes')
async def encrypt_route(request: Request):
  data = await request.json()
  appkey = data['appkey']
  encrypted_Data = encrypt_by_symmetric_key(data['data'], appkey)
  return {'encrypted_Data': encrypted_Data}


@app.post('/decryptsek')
async def decrypt_route(request: Request):
  data = await request.json()
  encrypted_sek = data['encrypted_sek']
  appkey = data['appkey']
  decrypted_sek = decrypt_sek_with_appkey(encrypted_sek, appkey)
  return {'decrypted_sek': decrypted_sek}


@app.post("/generate_qr")
async def generate_qr(QRdata: dict):
    qr_data = QRdata.get("Data", "")  # Get the value of the "Data" key, defaulting to empty string if not found

    qr = qrcode.QRCode(
        version=None,  # Set version to None for automatic sizing
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=0,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_image = qr_image.resize((136, 136))
    
    image_bytes = BytesIO()
    qr_image.save("qr_code.png")
    
    return FileResponse("qr_code.png", media_type="image/png")
  

@app.post("/edit_pdf")
async def edit_pdf(pdffile: UploadFile, qrData: str, barcodeData: str):
    # Save the uploaded PDF file
    with open("input.pdf", "wb") as f:
        shutil.copyfileobj(pdffile.file, f)

    qr = qrcode.QRCode(
        version=None,  # Set version to None for automatic sizing
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=0,
    )
    qr.add_data(qrData)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_image = qr_image.resize((136, 136))
    qr_image.save("qr_code.png")

    ean = barcode.get("ean13", barcodeData, writer=ImageWriter())
    # Now we look if the checksum was added
    ean.get_fullcode()
    ean.writer.dpi = 121
    filename = ean.save("ean13")
    options = dict(text_distance=3.2)
    filename = ean.save("bar_code", options)

    imageQr = Image.open("qr_code.png")
    imageBAr = Image.open("bar_code.png")

    flipped_image = imageQr.transpose(Image.FLIP_TOP_BOTTOM)
    flipped_image.save("qr_code.png")
    flipped_image = imageBAr.transpose(Image.FLIP_TOP_BOTTOM)
    flipped_image.save("bar_code.png")

    doc = fit.open("input.pdf")
    x = 2020
    y = 301
    width = 330
    height = 330

    rect = fit.Rect(x, y, x + width, y + height)

    x = 1050
    y = -2250
    width = 350
    height = 350
    rect1 = fit.Rect(x, y, x + width, y + height)

    image_path = "qr_code.png"
    with open(image_path, "rb") as f:
        image_data = f.read()

    image_path = "bar_code.png"
    with open(image_path, "rb") as f:
        image_databar = f.read()

    image_stream = BytesIO(image_data)
    image_databar = BytesIO(image_databar)

    page = doc[0]
    for Page in doc:
        page.insert_image(rect, stream=image_stream)
        page.insert_image(rect1, stream=image_databar)
    doc.save("new1.pdf")

    # Return the modified PDF file
    return FileResponse("new1.pdf", media_type="application/pdf")
  
@app.get("/gstin-search/{gstin}")
def gstin_search(gstin: str):
    url = 'https://app.signalx.ai/apps/gst-verification/gstin-overview/'
    response = requests.get(url + gstin)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Error retrieving GSTIN data")

    json_data = json.loads(response.content.decode('utf-8'))

    trade_name = json_data['trade_name']
    principal_place_of_business = json_data['principal_place_of_business']

    split_string = principal_place_of_business.split(',')[:6]

    result = gstin+ ": " + trade_name + ": " + principal_place_of_business

    return result

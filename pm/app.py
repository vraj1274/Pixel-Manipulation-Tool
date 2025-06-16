from flask import Flask, render_template, request, send_from_directory
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import os
import io

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
KEY_FOLDER = 'keys'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

PRIVATE_KEY_FILE = os.path.join(KEY_FOLDER, 'private.pem')
PUBLIC_KEY_FILE = os.path.join(KEY_FOLDER, 'public.pem')

# RSA Key Generation & Persistence
if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(key.export_key())
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(key.publickey().export_key())

# Load RSA keys
with open(PRIVATE_KEY_FILE, 'rb') as f:
    private_key = f.read()
with open(PUBLIC_KEY_FILE, 'rb') as f:
    public_key = f.read()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files.get('file')
    if not file or file.filename == '':
        return "No file selected for encryption", 400

    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    # Load image and extract byte data
    try:
        img = Image.open(input_path)
    except Exception:
        return "Invalid image file", 400

    img_format = img.format
    img_byte_io = io.BytesIO()
    img.save(img_byte_io, format=img_format)
    img_bytes = img_byte_io.getvalue()

    # AES Encryption
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(img_bytes, AES.block_size))

    # RSA Encryption of AES key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    enc_filename = filename + '.bin'
    enc_path = os.path.join(ENCRYPTED_FOLDER, enc_filename)

    with open(enc_path, 'wb') as f:
        f.write(len(encrypted_aes_key).to_bytes(2, 'big'))  # Key length
        f.write(encrypted_aes_key)
        f.write(cipher_aes.iv)
        f.write(img_format.encode('utf-8').ljust(10, b' '))  # Store format (fixed 10 bytes)
        f.write(ciphertext)

    return render_template('download.html', filename=enc_filename, message="✅ Image encrypted successfully!")

@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files.get('file')
    if not file or file.filename == '':
        return "No file selected for decryption", 400

    filename = secure_filename(file.filename)
    enc_path = os.path.join(ENCRYPTED_FOLDER, filename)
    file.save(enc_path)

    with open(enc_path, 'rb') as f:
        key_len = int.from_bytes(f.read(2), 'big')
        encrypted_aes_key = f.read(key_len)
        iv = f.read(16)
        img_format = f.read(10).strip().decode()
        ciphertext = f.read()

    # Decrypt AES key
    try:
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    except ValueError:
        return "❌ RSA decryption failed!", 400

    # Decrypt image bytes
    try:
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
    except ValueError:
        return "❌ AES decryption failed!", 400

    # Reconstruct and save image
    try:
        img = Image.open(io.BytesIO(decrypted_data))
        dec_filename = 'decrypted_' + filename.replace('.bin', f'.{img_format.lower()}')
        dec_path = os.path.join(DECRYPTED_FOLDER, dec_filename)
        img.save(dec_path, format=img_format)
    except Exception:
        return "❌ Failed to reconstruct image.", 400

    return render_template('download.html', filename=dec_filename, message="✅ Image decrypted successfully!")

@app.route('/download/<filename>')
def download_file(filename):
    folder = DECRYPTED_FOLDER if 'decrypted_' in filename else ENCRYPTED_FOLDER
    return send_from_directory(folder, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

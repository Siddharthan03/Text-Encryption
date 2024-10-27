from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)

# AES key generation
def generate_aes_key():
    return os.urandom(32)  # 32 bytes for AES-256

# DES key generation
def generate_des_key():
    return os.urandom(8)  # 8 bytes for DES

# AES encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

# AES decryption
def aes_decrypt(ciphertext, key):
    iv = base64.b64decode(ciphertext[:24])
    ct = base64.b64decode(ciphertext[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# DES encryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ct_bytes = cipher.encrypt(padded_text)
    return base64.b64encode(ct_bytes).decode('utf-8')

# DES decryption
def des_decrypt(ciphertext, key):
    ct = base64.b64decode(ciphertext)
    cipher = DES.new(key, DES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt.decode('utf-8')

# RSA encryption and decryption
def rsa_encrypt(plaintext, public_key_base64):
    public_key_der = base64.b64decode(public_key_base64)
    public_key = RSA.import_key(public_key_der)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def rsa_decrypt(ciphertext, private_key_base64):
    try:
        private_key_der = base64.b64decode(private_key_base64)
        private_key = RSA.import_key(private_key_der)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted = cipher_rsa.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode('utf-8')
    except (ValueError, TypeError) as e:
        raise ValueError("This is not a valid private key") from e

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    aes_key = None
    des_key = None
    generated_private_key = None  # Only store the private key

    if request.method == 'POST':
        action = request.form.get('action')
        method = request.form.get('method')
        key = request.form.get('key').strip()
        text = request.form.get('text').strip()

        try:
            if method == 'aes':
                if key == '':  # Generate a new key if none is provided
                    key = generate_aes_key()
                    aes_key = base64.b64encode(key).decode('utf-8')  # Save for display
                else:
                    key = base64.b64decode(key)  # Decode provided key
                
                if action == 'encrypt':
                    result = aes_encrypt(text, key)
                else:
                    result = aes_decrypt(text, key)

            elif method == 'des':
                if key == '':  # Generate a new key if none is provided
                    key = generate_des_key()
                    des_key = base64.b64encode(key).decode('utf-8')  # Save for display
                else:
                    key = base64.b64decode(key)  # Decode provided key
                
                if action == 'encrypt':
                    result = des_encrypt(text, key)
                else:
                    result = des_decrypt(text, key)

            elif method == 'rsa':
                if action == 'encrypt':
                    # Generate RSA keys only when encrypting
                    rsa_keys = RSA.generate(2048)
                    generated_private_key = base64.b64encode(rsa_keys.export_key()).decode('utf-8')
                    public_key_base64 = base64.b64encode(rsa_keys.publickey().export_key()).decode('utf-8')
                    print("Generated Private Key:", generated_private_key)  # Debugging output

                    result = rsa_encrypt(text, public_key_base64)  # Use the public key for encryption

                else:  # Decrypt action using the provided private key
                    if not key:  # If no private key is provided for decryption
                        error = "Private Key Required for Decryption"
                    else:
                        try:
                            result = rsa_decrypt(text, key)  # Attempt to decrypt with the provided private key
                        except ValueError as e:
                            error = str(e)

        except Exception as e:
            error = f"Error: {str(e)}"
    
    return render_template('index.html', 
                           result=result, 
                           error=error,
                           aes_key=aes_key,
                           des_key=des_key,
                           generated_private_key=generated_private_key)

@app.route('/generate_rsa_keys', methods=['GET'])
def generate_rsa_keys():
    rsa_keys = RSA.generate(2048)
    public_key = base64.b64encode(rsa_keys.publickey().export_key()).decode('utf-8')
    private_key = base64.b64encode(rsa_keys.export_key()).decode('utf-8')
    
    return jsonify({
        'public_key': public_key,
        'private_key': private_key
    })

if __name__ == '__main__':
    app.run(debug=True)
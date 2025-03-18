import math
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from sympy import mod_inverse, randprime
from ttkbootstrap import Style


def select_file(title, filetypes):
    file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    return file_path


def generate_keypair(bit_length):
    if not os.path.exists('keys'):
        os.makedirs('keys')

    # Generate two distinct prime numbers p and q.
    p = randprime(2 ** (bit_length // 2), 2 ** (bit_length // 2 + 1) - 1)
    q = randprime(2 ** (bit_length // 2), 2 ** (bit_length // 2 + 1) - 1)
    while p == q:
        q = randprime(2 ** (bit_length // 2), 2 ** (bit_length // 2 + 1) - 1)

    # Computing n = p * q
    n = p * q

    # Calculating the Euler's alpha-cut of n.
    phi = (p - 1) * (q - 1)

    # Choosing an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1.
    # e = random.randrange(2, phi)

    e = 65537  # Commonly used Exponent
    if math.gcd(e, phi) != 1:
        raise ValueError(f"e ({e}) and phi ({phi}) are not coprime")

    # g = math.gcd(e, phi)
    # while g != 1:
    # e = random.randrange(2, phi)
    # g = math.gcd(e, phi)

    # Determining d as d ≡ e^(-1) (mod phi(n)).
    d = mod_inverse(e, phi)

    # Creating the RSA keys.
    key_params = (n, e, d, p, q)
    key = RSA.construct(key_params)

    private_key = key.export_key()
    with open("keys/private.pem", "wb") as priv_file:
        priv_file.write(private_key)

    public_key = key.publickey().export_key()
    with open("keys/public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    messagebox.showinfo("Success", "Keys successfully generated!")


def encrypt_file(pub_key_file, file_to_encrypt):
    try:

        with open(pub_key_file, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())

        with open(file_to_encrypt, 'rb') as f:
            data = f.read()

        symmetric_key = get_random_bytes(32)  # Generate a 256-bit symmetric key for AES

        cipher_aes = AES.new(symmetric_key, AES.MODE_GCM)  # Encrypt the data
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        cipher_rsa = PKCS1_OAEP.new(public_key)  # Encrypt the symmetric key with the public RSA key
        encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)

        encrypted_file = file_to_encrypt + '.enc'

        with open(encrypted_file, 'wb') as f_enc:  # Write the encrypted data to the file
            for x in (encrypted_symmetric_key, cipher_aes.nonce, tag, ciphertext):
                f_enc.write(x)

        messagebox.showinfo("Success", "File encrypted successfully!")

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


def decrypt_file(priv_key_file, file_to_decrypt):
    try:
        with open(priv_key_file, 'rb') as key_file:
            private_key = RSA.import_key(key_file.read())

        with open(file_to_decrypt, 'rb') as f_enc:
            encrypted_symmetric_key = f_enc.read(private_key.size_in_bytes())
            nonce = f_enc.read(16)
            tag = f_enc.read(16)
            ciphertext = f_enc.read()

        cipher_rsa = PKCS1_OAEP.new(private_key)  # Decrypt the symmetric key with the RSA private key
        symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)

        # Decrypt the data with AES using the decrypted symmetric key
        cipher_aes = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        file_name, file_extension = os.path.splitext(file_to_decrypt)
        original_file_name = os.path.basename(file_name)

        decrypted_file_name = f'decrypted_{original_file_name}'

        with open(decrypted_file_name, 'wb') as f_dec:
            f_dec.write(data)

        messagebox.showinfo("Success", "File decrypted successfully!")

    except ValueError as e:  # Catch the ValueError, which indicates a tag mismatch
        messagebox.showerror("Tampering detected", "The file has been tampered with or corrupted.")
    except Exception as e:  # Catch other exceptions
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")



def on_encrypt():
    pub_key_file = select_file("Select the public key file", [("PEM files", "*.pem")])
    if not pub_key_file:
        return

    file_to_encrypt = select_file("Select a file to encrypt", [("All files", "*.*")])
    if not file_to_encrypt:
        return

    encrypt_file(pub_key_file, file_to_encrypt)


def on_decrypt():
    priv_key_file = select_file("Select the private key file", [("PEM files", "*.pem")])
    if not priv_key_file:
        return

    file_to_decrypt = select_file("Select a file to decrypt", [("All files", "*.*")])
    if not file_to_decrypt:
        return

    decrypt_file(priv_key_file, file_to_decrypt)


def asymmetric_gui():
    root = tk.Tk()
    root.title("Asymmetric Encryption/Decryption")
    style = Style(theme='superhero')

    app_frame = ttk.Frame(root, padding="30 15 30 15")
    app_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)

    btn_generate_keys = ttk.Button(app_frame, text="Generate Keypair", command=lambda: generate_keypair(2048))  # 3072
    btn_generate_keys.grid(column=0, row=0, pady=10)

    btn_encrypt = ttk.Button(app_frame, text="Encrypt File", command=on_encrypt)
    btn_encrypt.grid(column=0, row=1, pady=10)

    btn_decrypt = ttk.Button(app_frame, text="Decrypt File", command=on_decrypt)
    btn_decrypt.grid(column=0, row=2, pady=10)

    root.mainloop()


if __name__ == "__main__":
    asymmetric_gui()

import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from ttkbootstrap import Style

# Konstants
SECRET_KEY_PATH = "keys/secret.key"


# Function to generate random Key
def generate_key():
    key = get_random_bytes(16)  # 16 for AES=128bits, 32 for AES-256bits

    save_key(key)
    messagebox.showinfo("Generated", "Keygenerated successfully!")


def save_key(key):
    with open(SECRET_KEY_PATH, "wb") as key_file:
        key_file.write(key)


def load_key():
    with open(SECRET_KEY_PATH, "rb") as key_file:
        key = key_file.read()
    return key


def launch_asymmetric_window():
    script_path = "asym.py"
    subprocess.Popen(["python", script_path])


# Optimized for windows
def open_file(filename):
    if sys.platform == "win32":
        os.startfile(filename)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, filename])


def open_and_read_file(filename):
    with open(filename, "rb") as f:
        return f.read()


def save_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)


def encrypt_file(cipher, read_filename, save_filename, mode, nonce):
    block = open_and_read_file(read_filename)
    header = block[:54]
    body = block[54:]

    if mode == AES.MODE_CTR:
        ciphertext = cipher.encrypt(body)
        result = header + nonce + ciphertext
    else:  # AES.MODE_ECB
        padded_body = pad(body, AES.block_size)
        ciphertext = cipher.encrypt(padded_body)
        result = header + ciphertext

    save_file(save_filename, result)


def decrypt_file(cipher, read_filename, decrypted_filename, mode, key):
    try:
        block = open_and_read_file(read_filename)
        header = block[:54]  # header size is fixed at 54 bytes

        if mode == AES.MODE_CTR:
            nonce = block[
                    54:62]  # Extract the nonce, which is 8 bytes long,can be adjusted if we have different header size
            encrypted_data = block[62:]  # The rest is encrypted data
            ctr = Counter.new(64, prefix=nonce)
            cipher = AES.new(key, mode, counter=ctr)  # re-initialize cipher with correct counter
            decrypted_body = cipher.decrypt(encrypted_data)
        else:  # AES.MODE_ECB
            encrypted_data = block[54:]
            decrypted_body = cipher.decrypt(encrypted_data)
            decrypted_body = unpad(decrypted_body, AES.block_size)

        result = header + decrypted_body
        save_file(decrypted_filename, result)

        return True
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def init_cipher(key, mode, counter=None):
    if mode == AES.MODE_CTR and counter is None:
        raise ValueError("CTR mode requires a counter")

    if mode == AES.MODE_CTR:
        return AES.new(key, mode, counter=counter)
    else:  # AES.MODE_ECB
        return AES.new(key, mode)


def main_gui():
    def on_encrypt():
        mode_choice = aes_mode_var.get()

        if mode_choice not in mode_mapping:
            messagebox.showerror("Error", "Invalid mode selection")
            return

        mode = mode_mapping[mode_choice]
        encrypted_filename = f"encrypted_{filename_mapping[mode_choice]}.bmp"

        read_filename = filedialog.askopenfilename(title="Select the BMP file to encrypt",
                                                   filetypes=[("BMP files", "*.bmp")])
        if not read_filename:
            return  # cancelled

        key = load_key()
        nonce = get_random_bytes(8)  # Generate a new nonce for each encryption
        if mode == AES.MODE_CTR:
            ctr = Counter.new(64, prefix=nonce)
            c_encrypt = init_cipher(key, mode, counter=ctr)
        else:  # AES.MODE_ECB
            c_encrypt = init_cipher(key, mode)

        encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, nonce)
        open_file(encrypted_filename)

        messagebox.showinfo("Success", "Encryption Successful!")
        lbl_result.config(text="Encryption Successful!")

    def on_decrypt():
        mode_choice = aes_mode_var.get()
        if mode_choice not in mode_mapping:
            messagebox.showerror("Error", "Invalid mode selection")
            return

        mode = mode_mapping[mode_choice]
        encrypted_filename = f"encrypted_{filename_mapping[mode_choice]}.bmp"
        decrypted_filename = f"decrypted_{filename_mapping[mode_choice]}.bmp"
        read_filename = filedialog.askopenfilename(title="Select the BMP file to Decrypt",
                                                   filetypes=[("BMP files", "*.bmp")])
        if not read_filename:
            return

        mode_in_filename = read_filename.split('_')[1].split('.')[0].upper()
        if mode_choice != aes_mode_options.get(mode_in_filename, ""):
            messagebox.showerror("Error",
                                 f"Mode mismatch: file was encrypted with {mode_in_filename}, but {aes_mode_options.get(mode_choice, 'unknown')} was selected for decryption.")
            return

        key = load_key()
        block = open_and_read_file(read_filename)

        if mode == AES.MODE_CTR:
            nonce = block[54:62]  # Extract the nonce from the file; adjust indices as necessary
            ctr = Counter.new(64, prefix=nonce)
            c_decrypt = init_cipher(key, mode, counter=ctr)
        else:  # AES.MODE_ECB
            c_decrypt = init_cipher(key, mode)

        decryption_successful = decrypt_file(c_decrypt, read_filename, decrypted_filename, mode,
                                             key)
        if not decryption_successful:
            lbl_result.config(text="Decryption failed for an unknown reason.", foreground="red")
        else:
            open_file(decrypted_filename)  # Only open the file if decryption was successful
            lbl_result.config(text="Decryption successful!", foreground="green")

    root = tk.Tk()
    root.title("Encryption / Decryption by Egzont")
    style = Style(theme='superhero')

    app_frame = ttk.Frame(root, padding="50 30 50 30")
    app_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
    app_frame.columnconfigure(0, weight=1)
    btn_generate_key_iv = ttk.Button(app_frame, text="Generate Key", command=generate_key,
                                     style='info.Outline.TButton')
    btn_generate_key_iv.grid(column=0, row=0, columnspan=2, sticky=tk.E + tk.W, pady=10)

    aes_mode_var = tk.StringVar()
    aes_mode_options = {
        "ECB": "1",
        "CTR": "2"
    }

    lbl_select_mode = ttk.Label(app_frame, text="Select the AES mode:")
    lbl_select_mode.grid(column=0, row=1, columnspan=2, sticky=tk.E + tk.W, pady=10)
    mode_mapping = {
        "1": AES.MODE_ECB,
        "2": AES.MODE_CTR
    }

    filename_mapping = {
        "1": "ECB",
        "2": "CTR"
    }

    for idx, (mode, val) in enumerate(aes_mode_options.items()):
        rb_mode = ttk.Radiobutton(app_frame, text=mode, variable=aes_mode_var, value=val, style='Accent.TButton')
        rb_mode.grid(column=0, row=idx + 2, columnspan=2, sticky=tk.E + tk.W,
                     pady=5)

    btn_encrypt = ttk.Button(app_frame, text="Encrypt File", command=on_encrypt, style='info.Outline.TButton')
    btn_encrypt.grid(column=0, row=4, pady=10)

    btn_decrypt = ttk.Button(app_frame, text="Decrypt File", command=on_decrypt, style='info.Outline.TButton')
    btn_decrypt.grid(column=1, row=4, pady=10)

    btn_asymmetric = ttk.Button(app_frame, text="Asymmetric Encryption/Decryption", command=launch_asymmetric_window,
                                style='info.Outline.TButton')
    btn_asymmetric.grid(column=0, row=5, columnspan=len(aes_mode_options), pady=10)  # Adjust the row as necessary

    lbl_result = ttk.Label(app_frame, text="")
    lbl_result.grid(column=0, row=7, columnspan=len(aes_mode_options))

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    for idx in range(len(aes_mode_options)):
        app_frame.columnconfigure(idx, weight=1)

    app_frame.rowconfigure((0, 1, 2, 3), weight=1)

    root.mainloop()


if __name__ == "__main__":
    main_gui()

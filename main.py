import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import hashlib
import getpass
import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from ttkbootstrap import Style

# Constants
SECRET_KEY_PATH = "keys/secret.key"
SALT_PATH = "keys/salt"
CONFIG_PATH = "config"


# Function to generate random Key with password protection
def generate_key(key_size=32):  # Default to AES-256
    try:
        if not os.path.exists("keys"):
            os.makedirs("keys")
            
        # Generate a random salt
        salt = get_random_bytes(16)
        with open(SALT_PATH, "wb") as salt_file:
            salt_file.write(salt)
            
        # Get password from user
        password_window = tk.Toplevel()
        password_window.title("Password Protection")
        password_window.geometry("300x150")
        
        password_var = tk.StringVar()
        confirm_var = tk.StringVar()
        
        ttk.Label(password_window, text="Enter password:").pack(pady=5)
        password_entry = ttk.Entry(password_window, show="*", textvariable=password_var)
        password_entry.pack(pady=5)
        
        ttk.Label(password_window, text="Confirm password:").pack(pady=5)
        confirm_entry = ttk.Entry(password_window, show="*", textvariable=confirm_var)
        confirm_entry.pack(pady=5)
        
        def submit_password():
            if password_var.get() == confirm_var.get():
                if len(password_var.get()) < 8:
                    messagebox.showerror("Error", "Password must be at least 8 characters")
                    return
                    
                # Generate key using PBKDF2
                password = password_var.get().encode()
                key = PBKDF2(password, salt, dkLen=key_size, count=1000000)  # High iteration count for security
                
                save_key(key)
                
                # Save key size to config
                with open(CONFIG_PATH, "w") as config:
                    config.write(f"KEY_SIZE={key_size}\n")
                    
                messagebox.showinfo("Success", "Key generated successfully!")
                password_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match")
        
        ttk.Button(password_window, text="Generate Key", command=submit_password).pack(pady=10)
        
        # Make sure the password window is modal
        password_window.transient(password_window.master)
        password_window.grab_set()
        password_window.wait_window()
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate key: {str(e)}")


def save_key(key):
    with open(SECRET_KEY_PATH, "wb") as key_file:
        key_file.write(key)


def load_key(password=None):
    if password is None:
        # Get password from user
        password = tk.simpledialog.askstring("Password", "Enter key password:", show="*")
        if not password:
            return None
    
    try:
        # Load salt and derive key using PBKDF2
        with open(SALT_PATH, "rb") as salt_file:
            salt = salt_file.read()
            
        # Get key size from config
        key_size = 32  # Default to AES-256
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as config:
                for line in config:
                    if line.startswith("KEY_SIZE="):
                        key_size = int(line.strip().split("=")[1])
                        break
        
        derived_key = PBKDF2(password.encode(), salt, dkLen=key_size, count=1000000)
        
        # Verify against stored key
        with open(SECRET_KEY_PATH, "rb") as key_file:
            stored_key = key_file.read()
            
        if derived_key == stored_key:
            return derived_key
        else:
            messagebox.showerror("Error", "Incorrect password")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load key: {str(e)}")
        return None


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


def encrypt_file(cipher, read_filename, save_filename, mode, nonce=None, iv=None):
    file_data = open_and_read_file(read_filename)
    
    # Check if this is a BMP file (has a 54-byte header)
    is_bmp = False
    if len(file_data) > 54 and file_data[:2] == b'BM':
        is_bmp = True
        header = file_data[:54]
        data_to_encrypt = file_data[54:]
    else:
        # For non-BMP files, encrypt the entire file
        header = b''
        data_to_encrypt = file_data
    
    # Log encryption information for security audit
    log_file = f"{save_filename}.log"
    with open(log_file, "w") as log:
        log.write(f"Encryption mode: {mode}\n")
        log.write(f"Original file: {read_filename}\n")
        log.write(f"Encrypted file: {save_filename}\n")
        log.write(f"File type: {'BMP' if is_bmp else 'Other'}\n")
        log.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
    
    # Metadata for file type detection during decryption
    metadata = bytearray(8)  # 8 bytes of metadata
    if is_bmp:
        metadata[0] = 1  # Flag for BMP file
    else:
        metadata[0] = 0  # Flag for other file types
    
    if mode == AES.MODE_CTR:
        ciphertext = cipher.encrypt(data_to_encrypt)
        result = header + metadata + nonce + ciphertext
    elif mode == AES.MODE_CBC:
        padded_data = pad(data_to_encrypt, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        result = header + metadata + iv + ciphertext
    elif mode == AES.MODE_GCM:
        ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)
        result = header + metadata + nonce + tag + ciphertext
    else:  # AES.MODE_ECB
        padded_data = pad(data_to_encrypt, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        result = header + metadata + ciphertext

    # Create a checksum of the encrypted data for integrity verification
    checksum = hashlib.sha256(result).digest()
    with open(f"{save_filename}.checksum", "wb") as f:
        f.write(checksum)
        
    save_file(save_filename, result)


def decrypt_file(cipher, read_filename, decrypted_filename, mode, key):
    try:
        block = open_and_read_file(read_filename)
        
        # Verify file integrity with checksum
        checksum_file = f"{read_filename}.checksum"
        if os.path.exists(checksum_file):
            with open(checksum_file, "rb") as f:
                stored_checksum = f.read()
            
            calculated_checksum = hashlib.sha256(block).digest()
            if calculated_checksum != stored_checksum:
                messagebox.showwarning("Security Warning", "File checksum does not match! The file may have been tampered with.")
        
        # Read metadata to determine file type
        is_bmp = False
        if len(block) > 2 and block[:2] == b'BM':  # Check for BMP signature
            is_bmp = True
            header = block[:54]
            metadata_start = 54
        else:
            header = b''
            metadata_start = 0
        
        # Read metadata block (8 bytes)
        metadata = block[metadata_start:metadata_start+8]
        
        # Override detection if metadata explicitly says it's a BMP
        if len(metadata) > 0 and metadata[0] == 1:
            is_bmp = True
        elif len(metadata) > 0 and metadata[0] == 0:
            is_bmp = False
        
        # Calculate offsets based on file type
        data_start = metadata_start + 8  # Skip 8 bytes for metadata
        
        if mode == AES.MODE_CTR:
            nonce = block[data_start:data_start+8]  # Extract the nonce (8 bytes)
            encrypted_data = block[data_start+8:]  # The rest is encrypted data
            ctr = Counter.new(64, prefix=nonce)
            cipher = AES.new(key, mode, counter=ctr)  # Re-initialize cipher with correct counter
            decrypted_data = cipher.decrypt(encrypted_data)
        elif mode == AES.MODE_CBC:
            iv = block[data_start:data_start+16]  # Extract the IV (16 bytes)
            encrypted_data = block[data_start+16:]
            cipher = AES.new(key, mode, iv=iv)  # Re-initialize cipher with correct IV
            decrypted_data = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_data, AES.block_size)
        elif mode == AES.MODE_GCM:
            nonce = block[data_start:data_start+16]  # Extract the nonce (16 bytes)
            tag = block[data_start+16:data_start+32]  # Extract the tag (16 bytes)
            encrypted_data = block[data_start+32:]
            cipher = AES.new(key, mode, nonce=nonce)
            try:
                decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
            except ValueError:
                messagebox.showerror("Security Error", "Authentication failed! The file has been tampered with.")
                return False
        else:  # AES.MODE_ECB
            encrypted_data = block[data_start:]
            decrypted_data = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_data, AES.block_size)

        # Combine header (if BMP) with decrypted data
        if is_bmp and len(header) == 54:
            result = header + decrypted_data
        else:
            result = decrypted_data
            
        save_file(decrypted_filename, result)
        
        # Log decryption information for security audit
        log_file = f"{decrypted_filename}.log"
        with open(log_file, "w") as log:
            log.write(f"Decryption mode: {mode}\n")
            log.write(f"Encrypted file: {read_filename}\n")
            log.write(f"Decrypted file: {decrypted_filename}\n")
            log.write(f"File type: {'BMP' if is_bmp else 'Other'}\n")
            log.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")

        return True
    except Exception as e:
        print(f"An error occurred: {e}")
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return False


def init_cipher(key, mode, counter=None, iv=None, nonce=None):
    if mode == AES.MODE_CTR and counter is None:
        raise ValueError("CTR mode requires a counter")
    elif mode == AES.MODE_CBC and iv is None:
        raise ValueError("CBC mode requires an initialization vector (IV)")
    elif mode == AES.MODE_GCM and nonce is None:
        raise ValueError("GCM mode requires a nonce")

    if mode == AES.MODE_CTR:
        return AES.new(key, mode, counter=counter)
    elif mode == AES.MODE_CBC:
        return AES.new(key, mode, iv=iv)
    elif mode == AES.MODE_GCM:
        return AES.new(key, mode, nonce=nonce)
    else:  # AES.MODE_ECB
        return AES.new(key, mode)


def main_gui():
    def on_encrypt():
        mode_choice = aes_mode_var.get()

        if mode_choice not in mode_mapping:
            messagebox.showerror("Error", "Invalid mode selection")
            return

        mode = mode_mapping[mode_choice]
        
        read_filename = filedialog.askopenfilename(title="Select the file to encrypt",
                                                   filetypes=[("All files", "*.*"), ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif"), 
                                                            ("Document files", "*.pdf *.doc *.docx *.txt")])
        if not read_filename:
            return  # cancelled
            
        # Get the original file extension and generate encrypted filename
        file_base, file_ext = os.path.splitext(read_filename)
        encrypted_filename = f"encrypted_{filename_mapping[mode_choice]}{file_ext}"

        key = load_key()
        if key is None:
            return  # Password entry was cancelled or incorrect
        
        if mode == AES.MODE_CTR:
            nonce = get_random_bytes(8)  # Generate a new nonce for each encryption
            ctr = Counter.new(64, prefix=nonce)
            c_encrypt = init_cipher(key, mode, counter=ctr)
            encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, nonce=nonce)
        elif mode == AES.MODE_CBC:
            iv = get_random_bytes(16)  # Generate a new IV for each encryption
            c_encrypt = init_cipher(key, mode, iv=iv)
            encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, iv=iv)
        elif mode == AES.MODE_GCM:
            nonce = get_random_bytes(16)  # Generate a new nonce for each encryption
            c_encrypt = init_cipher(key, mode, nonce=nonce)
            encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, nonce=nonce)
        else:  # AES.MODE_ECB
            c_encrypt = init_cipher(key, mode)
            encrypt_file(c_encrypt, read_filename, encrypted_filename, mode)
        
        open_file(encrypted_filename)

        messagebox.showinfo("Success", "Encryption Successful!")
        lbl_result.config(text="Encryption Successful!", foreground="green")

    def on_decrypt():
        mode_choice = aes_mode_var.get()
        if mode_choice not in mode_mapping:
            messagebox.showerror("Error", "Invalid mode selection")
            return

        mode = mode_mapping[mode_choice]
        
        read_filename = filedialog.askopenfilename(title="Select the file to Decrypt",
                                                   filetypes=[("All files", "*.*"), ("Encrypted files", "*.enc")])
        if not read_filename:
            return

        # Try to determine the encryption mode from the file extension or name pattern
        try:
            if "_ECB" in read_filename:
                detected_mode = "ECB"
            elif "_CTR" in read_filename:
                detected_mode = "CTR"
            elif "_CBC" in read_filename:
                detected_mode = "CBC"
            elif "_GCM" in read_filename:
                detected_mode = "GCM"
            else:
                detected_mode = filename_mapping[mode_choice]
                
            if detected_mode != filename_mapping[mode_choice]:
                if not messagebox.askyesno("Mode Mismatch Warning", 
                                        f"The file appears to be encrypted with {detected_mode}, but you selected {filename_mapping[mode_choice]}. Continue anyway?"):
                    return
        except:
            pass

        # Get the original file extension and generate decrypted filename
        file_base, file_ext = os.path.splitext(read_filename)
        if file_ext.lower() == '.enc':
            # For .enc files, try to determine original extension from the filename
            orig_ext = '.bin'  # Default extension if we can't determine
            # Look for known extensions in the filename
            for ext in ['.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.bmp', '.gif']:
                if ext in file_base.lower():
                    orig_ext = ext
                    break
        else:
            orig_ext = file_ext  # Keep the same extension
            
        decrypted_filename = f"decrypted_file{orig_ext}"

        key = load_key()
        if key is None:
            return  # Password entry was cancelled or incorrect
            
        # Set up decryption parameters based on mode
        if mode == AES.MODE_CTR:
            # For CTR mode, nonce is extracted during decryption
            c_decrypt = init_cipher(key, mode, counter=Counter.new(64))  # Will be reinitialized during decryption
        elif mode == AES.MODE_CBC:
            # For CBC mode, IV is extracted during decryption
            c_decrypt = AES.new(key, mode, iv=b'\0'*16)  # Will be reinitialized during decryption
        elif mode == AES.MODE_GCM:
            # For GCM mode, nonce is extracted during decryption
            c_decrypt = AES.new(key, mode, nonce=b'\0'*16)  # Will be reinitialized during decryption
        else:  # AES.MODE_ECB
            c_decrypt = init_cipher(key, mode)

        decryption_successful = decrypt_file(c_decrypt, read_filename, decrypted_filename, mode, key)
        if not decryption_successful:
            lbl_result.config(text="Decryption failed.", foreground="red")
        else:
            open_file(decrypted_filename)  # Only open the file if decryption was successful
            lbl_result.config(text="Decryption successful!", foreground="green")

    def show_security_info():
        info_window = tk.Toplevel()
        info_window.title("Security Information")
        info_window.geometry("500x400")
        
        info_text = ttk.Label(info_window, text="""Security Features:
        
1. Password-Protected Keys:
   - AES-256 encryption by default
   - Keys derived using PBKDF2 with 1,000,000 iterations
   - Secure salt generation

2. Multiple Encryption Modes:
   - ECB: Simple but less secure (not recommended for sensitive data)
   - CTR: Stream cipher mode, no padding required
   - CBC: Block cipher with initialization vector for security
   - GCM: Authenticated encryption providing confidentiality and integrity

3. Integrity Protection:
   - SHA-256 checksums for encrypted files
   - GCM mode provides built-in authentication
   - Tamper detection during decryption

4. Audit Logging:
   - Encryption and decryption operations are logged
   - Timestamps and file information recorded

Best Practices:
   - Use GCM mode for sensitive data
   - Use strong passwords (minimum 8 characters)
   - Regularly rotate encryption keys
   - Keep private keys secure
        """, justify="left", wraplength=480)
        info_text.pack(padx=10, pady=10, expand=True, fill="both")
        
        ttk.Button(info_window, text="Close", command=info_window.destroy).pack(pady=10)

    root = tk.Tk()
    root.title("Advanced Encryption / Decryption Tool")
    style = Style(theme='superhero')

    app_frame = ttk.Frame(root, padding="50 30 50 30")
    app_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
    app_frame.columnconfigure(0, weight=1)
    
    # Key size selection
    key_size_frame = ttk.LabelFrame(app_frame, text="Key Size")
    key_size_frame.grid(column=0, row=0, columnspan=2, sticky=tk.E + tk.W, pady=5)
    
    key_size_var = tk.IntVar(value=32)  # Default to AES-256
    ttk.Radiobutton(key_size_frame, text="AES-128 (16 bytes)", variable=key_size_var, value=16).pack(anchor="w", padx=5)
    ttk.Radiobutton(key_size_frame, text="AES-192 (24 bytes)", variable=key_size_var, value=24).pack(anchor="w", padx=5)
    ttk.Radiobutton(key_size_frame, text="AES-256 (32 bytes)", variable=key_size_var, value=32).pack(anchor="w", padx=5)
    
    # Button to generate key with selected key size
    btn_generate_key_iv = ttk.Button(app_frame, text="Generate Key", 
                                     command=lambda: generate_key(key_size_var.get()),
                                     style='info.Outline.TButton')
    btn_generate_key_iv.grid(column=0, row=1, columnspan=2, sticky=tk.E + tk.W, pady=10)

    # Encryption mode selection
    aes_mode_var = tk.StringVar()
    aes_mode_options = {
        "ECB (Electronic Codebook)": "1",
        "CTR (Counter)": "2",
        "CBC (Cipher Block Chaining)": "3",
        "GCM (Galois/Counter Mode)": "4"
    }

    mode_frame = ttk.LabelFrame(app_frame, text="Encryption Mode")
    mode_frame.grid(column=0, row=2, columnspan=2, sticky=tk.E + tk.W, pady=10)
    
    mode_mapping = {
        "1": AES.MODE_ECB,
        "2": AES.MODE_CTR,
        "3": AES.MODE_CBC,
        "4": AES.MODE_GCM
    }

    filename_mapping = {
        "1": "ECB",
        "2": "CTR",
        "3": "CBC",
        "4": "GCM"
    }

    for idx, (mode, val) in enumerate(aes_mode_options.items()):
        rb_mode = ttk.Radiobutton(mode_frame, text=mode, variable=aes_mode_var, value=val)
        rb_mode.pack(anchor="w", padx=5, pady=2)
        
        # Add mode descriptions
        if val == "1":
            ttk.Label(mode_frame, text="    Simple but less secure, not recommended for sensitive data", 
                     font=("Helvetica", 8), foreground="gray").pack(anchor="w", padx=25, pady=0)
        elif val == "2":
            ttk.Label(mode_frame, text="    Stream cipher mode, good for large files", 
                     font=("Helvetica", 8), foreground="gray").pack(anchor="w", padx=25, pady=0)
        elif val == "3":
            ttk.Label(mode_frame, text="    Block cipher with initialization vector for better security", 
                     font=("Helvetica", 8), foreground="gray").pack(anchor="w", padx=25, pady=0)
        elif val == "4":
            ttk.Label(mode_frame, text="    Authenticated encryption, provides integrity protection (recommended)", 
                     font=("Helvetica", 8), foreground="gray").pack(anchor="w", padx=25, pady=0)

    # Action buttons
    btn_frame = ttk.Frame(app_frame)
    btn_frame.grid(column=0, row=3, columnspan=2, sticky=tk.E + tk.W, pady=10)
    
    btn_encrypt = ttk.Button(btn_frame, text="Encrypt File", command=on_encrypt, style='success.TButton')
    btn_encrypt.pack(side="left", padx=5, pady=10, expand=True, fill="x")

    btn_decrypt = ttk.Button(btn_frame, text="Decrypt File", command=on_decrypt, style='info.TButton')
    btn_decrypt.pack(side="left", padx=5, pady=10, expand=True, fill="x")

    btn_security_info = ttk.Button(app_frame, text="Security Information", command=show_security_info, 
                                 style='secondary.Outline.TButton')
    btn_security_info.grid(column=0, row=4, columnspan=1, sticky=tk.E + tk.W, pady=5)
    
    btn_asymmetric = ttk.Button(app_frame, text="Asymmetric Encryption", command=launch_asymmetric_window,
                                style='primary.Outline.TButton')
    btn_asymmetric.grid(column=1, row=4, columnspan=1, sticky=tk.E + tk.W, pady=5)

    lbl_result = ttk.Label(app_frame, text="")
    lbl_result.grid(column=0, row=5, columnspan=2, pady=10)

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    app_frame.columnconfigure(0, weight=1)
    app_frame.columnconfigure(1, weight=1)

    # Set the first mode as default
    aes_mode_var.set("4")  # Default to GCM (most secure)

    root.mainloop()


if __name__ == "__main__":
    main_gui()

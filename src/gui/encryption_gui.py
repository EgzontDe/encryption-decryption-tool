"""
GUI module for symmetric encryption operations.
"""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import logging

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from ttkbootstrap import Style

from src.crypto.key_manager import generate_key, load_key
from src.crypto.symmetric import init_cipher, encrypt_file, decrypt_file
from src.crypto.utils import open_file, get_app_config, save_app_config

# Set up logging
logger = logging.getLogger(__name__)

def launch_asymmetric_window():
    """Launch the asymmetric encryption window."""
    try:
        script_path = "src/core/asym.py"
        subprocess.Popen([sys.executable, script_path])
        logger.info("Launched asymmetric encryption window")
    except Exception as e:
        logger.error(f"Failed to launch asymmetric window: {str(e)}")
        messagebox.showerror("Error", f"Failed to launch asymmetric encryption: {str(e)}")

def show_security_info(parent):
    """Display security information dialog."""
    info_window = tk.Toplevel(parent)
    info_window.title("Security Information")
    info_window.geometry("500x400")

    info_text = ttk.Label(
        info_window,
        text="""Security Features:
    
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
    """,
        justify="left",
        wraplength=480,
    )
    info_text.pack(padx=10, pady=10, expand=True, fill="both")

    ttk.Button(info_window, text="Close", command=info_window.destroy).pack(pady=10)

def main_gui():
    """Initialize and run the main GUI application."""
    def on_encrypt():
        """Handle the encrypt button click event."""
        mode_choice = aes_mode_var.get()

        if mode_choice not in mode_mapping:
            messagebox.showerror("Error", "Invalid mode selection")
            return

        mode = mode_mapping[mode_choice]
        
        read_filename = filedialog.askopenfilename(
            title="Select the file to encrypt", 
            filetypes=[
                ("All files", "*.*"), 
                ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif"), 
                ("Document files", "*.pdf *.doc *.docx *.txt")
            ]
        )
        if not read_filename:
            return  # cancelled
            
        # Get the original file extension and generate encrypted filename
        file_base, file_ext = os.path.splitext(read_filename)
        encrypted_filename = f"encrypted_{filename_mapping[mode_choice]}{file_ext}"

        key = load_key()
        if key is None:
            return

        try:
            if mode == AES.MODE_CTR:
                nonce = get_random_bytes(8)  # Generate a new nonce for each encryption
                ctr = Counter.new(64, prefix=nonce)
                c_encrypt = init_cipher(key, mode, counter=ctr)
                encrypt_success = encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, nonce=nonce)
            elif mode == AES.MODE_CBC:
                iv = get_random_bytes(16)  # Generate a new IV for each encryption
                c_encrypt = init_cipher(key, mode, iv=iv)
                encrypt_success = encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, iv=iv)
            elif mode == AES.MODE_GCM:
                nonce = get_random_bytes(16)  # Generate a new nonce for each encryption
                c_encrypt = init_cipher(key, mode, nonce=nonce)
                encrypt_success = encrypt_file(c_encrypt, read_filename, encrypted_filename, mode, nonce=nonce)
            else:  # AES.MODE_ECB
                c_encrypt = init_cipher(key, mode)
                encrypt_success = encrypt_file(c_encrypt, read_filename, encrypted_filename, mode)

            if encrypt_success:
                open_file(encrypted_filename)
                messagebox.showinfo("Success", "Encryption Successful!")
                lbl_result.config(text="Encryption Successful!", foreground="green")
                
                # Update last used mode in config
                config = get_app_config()
                config["default_mode"] = filename_mapping[mode_choice]
                save_app_config(config)
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            lbl_result.config(text=f"Encryption failed: {str(e)}", foreground="red")

    def on_decrypt():
        """Handle the decrypt button click event."""
        mode_choice = aes_mode_var.get()
        if mode_choice not in mode_mapping:
            messagebox.showerror("Error", "Invalid mode selection")
            return

        mode = mode_mapping[mode_choice]
        
        read_filename = filedialog.askopenfilename(
            title="Select the file to Decrypt", 
            filetypes=[("All files", "*.*")]
        )
        if not read_filename:
            return

        try:
            # Try to detect encryption mode from filename
            detected_mode = None
            for mode_id, mode_name in filename_mapping.items():
                if f"_{mode_name}" in read_filename:
                    detected_mode = mode_name
                    break

            if detected_mode and detected_mode != filename_mapping[mode_choice]:
                if not messagebox.askyesno(
                    "Mode Mismatch Warning",
                    f"The file appears to be encrypted with {detected_mode}, but you selected {filename_mapping[mode_choice]}. Continue anyway?",
                ):
                    return
        except Exception as e:
            logger.warning(f"Failed to detect encryption mode: {str(e)}")

        key = load_key()
        if key is None:
            return

        try:
            # Determine output file name
            file_base, file_ext = os.path.splitext(read_filename)
            decrypted_filename = f"decrypted_file{file_ext}"
            
            # Set up decryption parameters based on mode
            if mode == AES.MODE_CTR:
                # For CTR mode, nonce is extracted during decryption
                c_decrypt = init_cipher(key, mode, counter=Counter.new(64))  # Will be reinitialized during decryption
            elif mode == AES.MODE_CBC:
                # For CBC mode, IV is extracted during decryption
                c_decrypt = AES.new(key, mode, iv=b"\0" * 16)  # Will be reinitialized during decryption
            elif mode == AES.MODE_GCM:
                # For GCM mode, nonce is extracted during decryption
                c_decrypt = AES.new(key, mode, nonce=b"\0" * 16)  # Will be reinitialized during decryption
            else:  # AES.MODE_ECB
                c_decrypt = init_cipher(key, mode)

            decryption_successful = decrypt_file(c_decrypt, read_filename, decrypted_filename, mode, key)
            if not decryption_successful:
                lbl_result.config(text="Decryption failed.", foreground="red")
            else:
                open_file(decrypted_filename)  # Only open the file if decryption was successful
                lbl_result.config(text="Decryption successful!", foreground="green")
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            lbl_result.config(text=f"Decryption failed: {str(e)}", foreground="red")

    # Initialize the main window
    root = tk.Tk()
    root.title("Advanced Encryption / Decryption Tool")
    style = Style(theme="superhero")

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
    btn_generate_key_iv = ttk.Button(
        app_frame, text="Generate Key", command=lambda: generate_key(root, key_size_var.get()), style="info.Outline.TButton"
    )
    btn_generate_key_iv.grid(column=0, row=1, columnspan=2, sticky=tk.E + tk.W, pady=10)

    # Encryption mode selection
    aes_mode_var = tk.StringVar()
    aes_mode_options = {
        "ECB (Electronic Codebook)": "1",
        "CTR (Counter)": "2",
        "CBC (Cipher Block Chaining)": "3",
        "GCM (Galois/Counter Mode)": "4",
    }

    mode_frame = ttk.LabelFrame(app_frame, text="Encryption Mode")
    mode_frame.grid(column=0, row=2, columnspan=2, sticky=tk.E + tk.W, pady=10)

    mode_mapping = {"1": AES.MODE_ECB, "2": AES.MODE_CTR, "3": AES.MODE_CBC, "4": AES.MODE_GCM}
    filename_mapping = {"1": "ECB", "2": "CTR", "3": "CBC", "4": "GCM"}

    for idx, (mode, val) in enumerate(aes_mode_options.items()):
        rb_mode = ttk.Radiobutton(mode_frame, text=mode, variable=aes_mode_var, value=val)
        rb_mode.pack(anchor="w", padx=5, pady=2)

        if val == "1":
            ttk.Label(
                mode_frame,
                text="    Simple but less secure, not recommended for sensitive data",
                font=("Helvetica", 8),
                foreground="gray",
            ).pack(anchor="w", padx=25, pady=0)
        elif val == "2":
            ttk.Label(
                mode_frame,
                text="    Stream cipher mode, good for large files",
                font=("Helvetica", 8),
                foreground="gray",
            ).pack(anchor="w", padx=25, pady=0)
        elif val == "3":
            ttk.Label(
                mode_frame,
                text="    Block cipher with initialization vector for better security",
                font=("Helvetica", 8),
                foreground="gray",
            ).pack(anchor="w", padx=25, pady=0)
        elif val == "4":
            ttk.Label(
                mode_frame,
                text="    Authenticated encryption, provides integrity protection (recommended)",
                font=("Helvetica", 8),
                foreground="gray",
            ).pack(anchor="w", padx=25, pady=0)

    # Action buttons
    btn_frame = ttk.Frame(app_frame)
    btn_frame.grid(column=0, row=3, columnspan=2, sticky=tk.E + tk.W, pady=10)

    btn_encrypt = ttk.Button(btn_frame, text="Encrypt File", command=on_encrypt, style="success.TButton")
    btn_encrypt.pack(side="left", padx=5, pady=10, expand=True, fill="x")

    btn_decrypt = ttk.Button(btn_frame, text="Decrypt File", command=on_decrypt, style="info.TButton")
    btn_decrypt.pack(side="left", padx=5, pady=10, expand=True, fill="x")

    btn_security_info = ttk.Button(
        app_frame, text="Security Information", command=lambda: show_security_info(root), style="secondary.Outline.TButton"
    )
    btn_security_info.grid(column=0, row=4, columnspan=1, sticky=tk.E + tk.W, pady=5)

    btn_asymmetric = ttk.Button(
        app_frame, text="Asymmetric Encryption", command=launch_asymmetric_window, style="primary.Outline.TButton"
    )
    btn_asymmetric.grid(column=1, row=4, columnspan=1, sticky=tk.E + tk.W, pady=5)

    lbl_result = ttk.Label(app_frame, text="")
    lbl_result.grid(column=0, row=5, columnspan=2, pady=10)

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    app_frame.columnconfigure(0, weight=1)
    app_frame.columnconfigure(1, weight=1)

    # Set default mode from config
    config = get_app_config()
    default_mode = config.get("default_mode", "GCM")
    
    # Find the correct key for the default mode
    for key, value in filename_mapping.items():
        if value == default_mode:
            aes_mode_var.set(key)
            break
    
    if not aes_mode_var.get():
        aes_mode_var.set("4")  # Default to GCM if not found

    root.mainloop()


if __name__ == "__main__":
    main_gui()
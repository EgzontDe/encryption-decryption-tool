import math
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss
from sympy import mod_inverse, randprime
from ttkbootstrap import Style
import datetime
import hashlib
import json

# Constants
KEY_DIRECTORY = 'keys'
KEY_METADATA_FILE = os.path.join(KEY_DIRECTORY, 'key_metadata.json')


def select_file(title, filetypes):
    file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    return file_path


def save_key_metadata(key_id, bit_length, creation_time, expiry_date=None):
    """Save metadata about generated keys"""
    if not os.path.exists(KEY_DIRECTORY):
        os.makedirs(KEY_DIRECTORY)
    
    metadata = {}
    
    # Load existing metadata if available
    if os.path.exists(KEY_METADATA_FILE):
        try:
            with open(KEY_METADATA_FILE, 'r') as f:
                metadata = json.load(f)
        except json.JSONDecodeError:
            # File exists but is not valid JSON, create new
            metadata = {}
    
    # Add new key metadata
    metadata[key_id] = {
        'bit_length': bit_length,
        'created': creation_time,
        'expires': expiry_date,
        'public_key': f"public_{key_id}.pem",
        'private_key': f"private_{key_id}.pem"
    }
    
    # Save updated metadata
    with open(KEY_METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=2)


def generate_key_id():
    """Generate a unique identifier for the key pair"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    random_component = os.urandom(4).hex()
    return f"{timestamp}_{random_component}"


def generate_keypair(bit_length):
    if bit_length < 2048:
        if not messagebox.askyesno("Security Warning", 
                              "Key lengths less than 2048 bits are not considered secure. Continue anyway?"):
            return
    
    try:
        if not os.path.exists(KEY_DIRECTORY):
            os.makedirs(KEY_DIRECTORY)
        
        # Generate key ID and creation time
        key_id = generate_key_id()
        creation_time = datetime.datetime.now().isoformat()
        
        # Ask for key password
        password = simpledialog.askstring("Key Protection", 
                                       "Enter a password to protect your private key (leave blank for no password):", 
                                       show="*")
        
        # Ask for expiry date
        expiry_input = simpledialog.askstring("Key Expiry", 
                                           "Enter key expiry period in days (leave blank for no expiry):")
        
        expiry_date = None
        if expiry_input and expiry_input.isdigit():
            days = int(expiry_input)
            expiry_date = (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat()
        
        # Generate the RSA key
        if bit_length <= 3072:
            # For smaller key sizes, use the manual prime number generation
            # Generate two distinct prime numbers p and q
            p = randprime(2 ** (bit_length // 2), 2 ** (bit_length // 2 + 1) - 1)
            q = randprime(2 ** (bit_length // 2), 2 ** (bit_length // 2 + 1) - 1)
            while p == q:
                q = randprime(2 ** (bit_length // 2), 2 ** (bit_length // 2 + 1) - 1)

            # Computing n = p * q
            n = p * q

            # Calculating the Euler's totient of n
            phi = (p - 1) * (q - 1)

            # Fixed public exponent
            e = 65537  # Commonly used exponent
            if math.gcd(e, phi) != 1:
                raise ValueError(f"e ({e}) and phi ({phi}) are not coprime")

            # Determine the private exponent
            d = mod_inverse(e, phi)

            # Creating the RSA keys
            key_params = (n, e, d, p, q)
            key = RSA.construct(key_params)
        else:
            # For larger key sizes, use Crypto.PublicKey.RSA.generate
            key = RSA.generate(bit_length)
        
        # Export keys
        if password:
            private_key_data = key.export_key(passphrase=password, pkcs=8, 
                                            protection="scryptAndAES128-CBC")
        else:
            private_key_data = key.export_key()
        
        public_key_data = key.publickey().export_key()
        
        # Save keys with the key ID in the filename
        private_key_file = os.path.join(KEY_DIRECTORY, f"private_{key_id}.pem")
        public_key_file = os.path.join(KEY_DIRECTORY, f"public_{key_id}.pem")
        
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(private_key_data)

        with open(public_key_file, "wb") as pub_file:
            pub_file.write(public_key_data)
        
        # Create symlinks for backward compatibility
        if os.path.exists(os.path.join(KEY_DIRECTORY, "private.pem")):
            os.remove(os.path.join(KEY_DIRECTORY, "private.pem"))
        if os.path.exists(os.path.join(KEY_DIRECTORY, "public.pem")):
            os.remove(os.path.join(KEY_DIRECTORY, "public.pem"))
            
        # On Windows, we can't create symlinks easily, so make copies instead
        with open(os.path.join(KEY_DIRECTORY, "private.pem"), "wb") as f:
            f.write(private_key_data)
        with open(os.path.join(KEY_DIRECTORY, "public.pem"), "wb") as f:
            f.write(public_key_data)
        
        # Save key metadata
        save_key_metadata(key_id, bit_length, creation_time, expiry_date)
        
        # Show success message
        message = f"Keys successfully generated!\n\nKey ID: {key_id}\nKey size: {bit_length} bits"
        if expiry_date:
            message += f"\nExpires: {expiry_date}"
        if password:
            message += "\nPassword protected: Yes"
        
        messagebox.showinfo("Success", message)
        
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed: {str(e)}")


def encrypt_file(pub_key_file, file_to_encrypt):
    try:
        # Load the public key
        with open(pub_key_file, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())
        
        # Check key expiry if metadata exists
        key_id = os.path.basename(pub_key_file).replace("public_", "").replace(".pem", "")
        if os.path.exists(KEY_METADATA_FILE) and "_" in key_id:  # Only check if it's a new format key
            with open(KEY_METADATA_FILE, 'r') as f:
                metadata = json.load(f)
                if key_id in metadata and metadata[key_id].get('expires'):
                    expiry_date = datetime.datetime.fromisoformat(metadata[key_id]['expires'])
                    if datetime.datetime.now() > expiry_date:
                        if not messagebox.askyesno("Key Expired", 
                                              f"The selected key expired on {expiry_date}. Continue anyway?"):
                            return

        # Read the input file
        with open(file_to_encrypt, 'rb') as f:
            data = f.read()

        # Generate a symmetric key for AES encryption
        symmetric_key = get_random_bytes(32)  # 256-bit key for AES
        
        # Generate an authentication key for HMAC
        auth_key = get_random_bytes(32)

        # Encrypt the data with AES-GCM
        cipher_aes = AES.new(symmetric_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        
        # Compute file hash for verification
        file_hash = SHA256.new(data).digest()
        
        # Add HMAC for additional integrity protection
        hmac_obj = HMAC.new(auth_key, digestmod=SHA256)
        hmac_obj.update(ciphertext)
        hmac_digest = hmac_obj.digest()

        # Encrypt the symmetric key and auth key with RSA
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted_keys = cipher_rsa.encrypt(symmetric_key + auth_key + file_hash)  # Combine keys and hash

        # Create a payload with version information and metadata
        metadata = {
            "filename": os.path.basename(file_to_encrypt),
            "encryption_time": datetime.datetime.now().isoformat(),
            "file_size": len(data),
            "algorithm": "AES-256-GCM",
            "key_id": key_id if "_" in key_id else "legacy"
        }
        metadata_json = json.dumps(metadata).encode('utf-8')
        
        # Determine the output file name
        file_name, file_ext = os.path.splitext(file_to_encrypt)
        encrypted_file = f"{file_name}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.enc"

        # Write the encrypted data to file
        with open(encrypted_file, 'wb') as f_enc:
            # Write header and metadata
            f_enc.write(b'ENCV2')  # Version identifier
            metadata_len = len(metadata_json).to_bytes(4, byteorder='big')
            f_enc.write(metadata_len)
            f_enc.write(metadata_json)
            
            # Write encrypted data components
            for component in (encrypted_keys, cipher_aes.nonce, tag, hmac_digest, ciphertext):
                # Write the length of each component for safer decryption
                component_len = len(component).to_bytes(4, byteorder='big')
                f_enc.write(component_len)
                f_enc.write(component)

        # Create a log entry
        log_file = f"{encrypted_file}.log"
        with open(log_file, "w") as log:
            log.write(f"Encryption Details:\n")
            log.write(f"  Source file: {file_to_encrypt}\n")
            log.write(f"  Encrypted file: {encrypted_file}\n")
            log.write(f"  Timestamp: {datetime.datetime.now().isoformat()}\n")
            log.write(f"  Key ID: {key_id if '_' in key_id else 'legacy'}\n")
            log.write(f"  Public key: {pub_key_file}\n")
            log.write(f"  Security features: AES-256-GCM, HMAC-SHA256, file hash verification\n")

        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


def decrypt_file(priv_key_file, file_to_decrypt):
    try:
        # Get password if the private key is password-protected
        try:
            with open(priv_key_file, 'rb') as key_file:
                key_data = key_file.read()
                if b'ENCRYPTED' in key_data:
                    password = simpledialog.askstring("Password Required", 
                                                   "Enter the password for this private key:", 
                                                   show="*")
                    if not password:
                        return  # User cancelled
                    private_key = RSA.import_key(key_data, passphrase=password)
                else:
                    private_key = RSA.import_key(key_data)
        except ValueError:
            messagebox.showerror("Error", "Incorrect password for private key")
            return
        
        # Check if this is a V2 format file (with metadata)
        with open(file_to_decrypt, 'rb') as f_enc:
            header = f_enc.read(5)
            
        if header == b'ENCV2':
            # This is a V2 encrypted file with metadata
            with open(file_to_decrypt, 'rb') as f_enc:
                f_enc.read(5)  # Skip version header
                
                # Read metadata
                metadata_len = int.from_bytes(f_enc.read(4), byteorder='big')
                metadata_json = f_enc.read(metadata_len)
                metadata = json.loads(metadata_json.decode('utf-8'))
                
                # Read encrypted components with their lengths
                encrypted_keys_len = int.from_bytes(f_enc.read(4), byteorder='big')
                encrypted_keys = f_enc.read(encrypted_keys_len)
                
                nonce_len = int.from_bytes(f_enc.read(4), byteorder='big')
                nonce = f_enc.read(nonce_len)
                
                tag_len = int.from_bytes(f_enc.read(4), byteorder='big')
                tag = f_enc.read(tag_len)
                
                hmac_len = int.from_bytes(f_enc.read(4), byteorder='big')
                hmac_digest = f_enc.read(hmac_len)
                
                ciphertext_len = int.from_bytes(f_enc.read(4), byteorder='big')
                ciphertext = f_enc.read(ciphertext_len)
                
                # Decrypt the keys
                cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
                decrypted_keys = cipher_rsa.decrypt(encrypted_keys)
                
                # Extract keys and hash
                symmetric_key = decrypted_keys[:32]
                auth_key = decrypted_keys[32:64]
                file_hash = decrypted_keys[64:]
                
                # Verify HMAC
                hmac_obj = HMAC.new(auth_key, digestmod=SHA256)
                hmac_obj.update(ciphertext)
                try:
                    hmac_obj.verify(hmac_digest)
                except ValueError:
                    messagebox.showerror("Security Error", "HMAC verification failed! The file has been tampered with.")
                    return False
                
                # Decrypt the data
                cipher_aes = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
                try:
                    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    messagebox.showerror("Security Error", "GCM authentication failed! The file has been tampered with.")
                    return False
                
                # Verify file hash
                if SHA256.new(data).digest() != file_hash:
                    messagebox.showerror("Security Error", "File hash verification failed! The file may be corrupted.")
                    return False
                
                # Determine output filename
                original_filename = metadata.get('filename', 'unknown')
                decrypted_file_name = f'decrypted_{original_filename}'
                
                # Save the decrypted data
                with open(decrypted_file_name, 'wb') as f_dec:
                    f_dec.write(data)
                
                # Create a log entry
                log_file = f"{decrypted_file_name}.log"
                with open(log_file, "w") as log:
                    log.write(f"Decryption Details:\n")
                    log.write(f"  Source file: {file_to_decrypt}\n")
                    log.write(f"  Decrypted file: {decrypted_file_name}\n")
                    log.write(f"  Timestamp: {datetime.datetime.now().isoformat()}\n")
                    log.write(f"  Original encryption time: {metadata.get('encryption_time', 'unknown')}\n")
                    log.write(f"  Key ID: {metadata.get('key_id', 'unknown')}\n")
                    log.write(f"  Private key: {priv_key_file}\n")
                    log.write(f"  Security checks passed: HMAC verification, GCM authentication, file hash verification\n")
                
                messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {decrypted_file_name}")
                return True
                
        else:
            # This is a legacy format file
            with open(file_to_decrypt, 'rb') as f_enc:
                encrypted_symmetric_key = f_enc.read(private_key.size_in_bytes())
                nonce = f_enc.read(16)
                tag = f_enc.read(16)
                ciphertext = f_enc.read()

            # Decrypt the symmetric key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)

            # Decrypt the data
            cipher_aes = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
            try:
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                messagebox.showerror("Tampering detected", "The file has been tampered with or corrupted.")
                return False

            # Determine output filename
            file_name, file_extension = os.path.splitext(file_to_decrypt)
            original_file_name = os.path.basename(file_name)
            decrypted_file_name = f'decrypted_{original_file_name}'

            # Save the decrypted data
            with open(decrypted_file_name, 'wb') as f_dec:
                f_dec.write(data)

            messagebox.showinfo("Success", "File decrypted successfully!")
            return True

    except ValueError as e:
        messagebox.showerror("Tampering detected", "The file has been tampered with or corrupted.")
        return False
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return False


def sign_file(priv_key_file, file_to_sign):
    try:
        # Get password if the private key is password-protected
        try:
            with open(priv_key_file, 'rb') as key_file:
                key_data = key_file.read()
                if b'ENCRYPTED' in key_data:
                    password = simpledialog.askstring("Password Required", 
                                                   "Enter the password for this private key:", 
                                                   show="*")
                    if not password:
                        return  # User cancelled
                    private_key = RSA.import_key(key_data, passphrase=password)
                else:
                    private_key = RSA.import_key(key_data)
        except ValueError:
            messagebox.showerror("Error", "Incorrect password for private key")
            return
            
        # Read the file
        with open(file_to_sign, 'rb') as f:
            data = f.read()
            
        # Create a hash of the file
        h = SHA256.new(data)
        
        # Create a signature
        signature_scheme = pss.new(private_key)
        signature = signature_scheme.sign(h)
        
        # Generate metadata
        key_id = os.path.basename(priv_key_file).replace("private_", "").replace(".pem", "")
        metadata = {
            "filename": os.path.basename(file_to_sign),
            "signing_time": datetime.datetime.now().isoformat(),
            "file_size": len(data),
            "hash_algorithm": "SHA-256",
            "signature_algorithm": "RSA-PSS",
            "key_id": key_id if "_" in key_id else "legacy"
        }
        metadata_json = json.dumps(metadata).encode('utf-8')
        
        # Save signature file
        signature_file = f"{file_to_sign}.sig"
        with open(signature_file, 'wb') as f_sig:
            # Write signature format version
            f_sig.write(b'SIGV1')
            
            # Write metadata length and metadata
            metadata_len = len(metadata_json).to_bytes(4, byteorder='big')
            f_sig.write(metadata_len)
            f_sig.write(metadata_json)
            
            # Write signature length and signature
            signature_len = len(signature).to_bytes(4, byteorder='big')
            f_sig.write(signature_len)
            f_sig.write(signature)
            
        messagebox.showinfo("Success", f"File signed successfully!\nSignature saved as: {signature_file}")
        
    except Exception as e:
        messagebox.showerror("Error", f"Signing failed: {str(e)}")


def verify_signature(pub_key_file, file_to_verify, signature_file=None):
    try:
        # Load the public key
        with open(pub_key_file, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())
            
        # If signature file not provided, try to find it
        if not signature_file:
            signature_file = f"{file_to_verify}.sig"
            if not os.path.exists(signature_file):
                signature_file = filedialog.askopenfilename(
                    title="Select signature file",
                    filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
                )
                if not signature_file:
                    return
        
        # Read the file to verify
        with open(file_to_verify, 'rb') as f:
            data = f.read()
            
        # Create a hash of the file
        h = SHA256.new(data)
        
        # Read the signature file
        with open(signature_file, 'rb') as f_sig:
            # Check signature format
            header = f_sig.read(5)
            if header != b'SIGV1':
                messagebox.showerror("Error", "Invalid signature file format")
                return
                
            # Read metadata
            metadata_len = int.from_bytes(f_sig.read(4), byteorder='big')
            metadata_json = f_sig.read(metadata_len)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Read signature
            signature_len = int.from_bytes(f_sig.read(4), byteorder='big')
            signature = f_sig.read(signature_len)
        
        # Verify the signature
        signature_scheme = pss.new(public_key)
        try:
            signature_scheme.verify(h, signature)
            
            # Show success message with metadata
            message = (
                f"Signature verification successful!\n\n"
                f"File: {os.path.basename(file_to_verify)}\n"
                f"Signed on: {metadata.get('signing_time', 'unknown')}\n"
                f"Key ID: {metadata.get('key_id', 'unknown')}\n"
                f"Algorithm: {metadata.get('signature_algorithm', 'RSA-PSS')}"
            )
            messagebox.showinfo("Verification Success", message)
            
        except (ValueError, TypeError):
            messagebox.showerror("Verification Failed", 
                             "The signature is invalid or the file has been modified after signing.")
            
    except Exception as e:
        messagebox.showerror("Error", f"Verification failed: {str(e)}")


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

    file_to_decrypt = select_file("Select a file to decrypt", [("Encrypted files", "*.enc"), ("All files", "*.*")])
    if not file_to_decrypt:
        return

    decrypt_file(priv_key_file, file_to_decrypt)


def on_sign():
    priv_key_file = select_file("Select the private key file", [("PEM files", "*.pem")])
    if not priv_key_file:
        return

    file_to_sign = select_file("Select a file to sign", [("All files", "*.*")])
    if not file_to_sign:
        return

    sign_file(priv_key_file, file_to_sign)


def on_verify():
    pub_key_file = select_file("Select the public key file", [("PEM files", "*.pem")])
    if not pub_key_file:
        return

    file_to_verify = select_file("Select a file to verify", [("All files", "*.*")])
    if not file_to_verify:
        return

    signature_file = select_file("Select the signature file", [("Signature files", "*.sig"), ("All files", "*.*")])
    if not signature_file:
        return

    verify_signature(pub_key_file, file_to_verify, signature_file)


def list_keys():
    if not os.path.exists(KEY_DIRECTORY):
        messagebox.showinfo("No Keys", "No keys have been generated yet.")
        return
        
    # List all PEM files in the keys directory
    key_files = [f for f in os.listdir(KEY_DIRECTORY) if f.endswith('.pem')]
    
    if not key_files:
        messagebox.showinfo("No Keys", "No keys found in the keys directory.")
        return
    
    # Load metadata if available
    metadata = {}
    if os.path.exists(KEY_METADATA_FILE):
        try:
            with open(KEY_METADATA_FILE, 'r') as f:
                metadata = json.load(f)
        except:
            pass
    
    # Create a new window to display the keys
    key_window = tk.Toplevel()
    key_window.title("Key Management")
    key_window.geometry("700x400")
    
    # Create a frame to hold the treeview
    frame = ttk.Frame(key_window, padding=10)
    frame.pack(fill="both", expand=True)
    
    # Create the treeview
    columns = ("Key ID", "Type", "Size", "Created", "Expires", "Status")
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
    
    # Define column headings
    for col in columns:
        tree.heading(col, text=col)
        if col == "Key ID":
            tree.column(col, width=150)
        elif col == "Type":
            tree.column(col, width=80)
        elif col == "Size":
            tree.column(col, width=60)
        elif col == "Created":
            tree.column(col, width=150)
        elif col == "Expires":
            tree.column(col, width=150)
        else:
            tree.column(col, width=80)
    
    # Add scrollbar
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    tree.pack(side="left", fill="both", expand=True)
    
    # Populate the tree with key information
    now = datetime.datetime.now()
    
    # First, handle the new format keys with metadata
    for key_id, info in metadata.items():
        key_type = "Unknown"
        if "public_key" in info and os.path.exists(os.path.join(KEY_DIRECTORY, info["public_key"])):
            key_type = "Public"
            size = info.get("bit_length", "Unknown")
            created = info.get("created", "Unknown")
            
            # Format the creation time
            if created != "Unknown":
                try:
                    created_dt = datetime.datetime.fromisoformat(created)
                    created = created_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            # Handle expiry
            expires = info.get("expires", "Never")
            status = "Valid"
            
            if expires != "Never":
                try:
                    expiry_dt = datetime.datetime.fromisoformat(expires)
                    expires = expiry_dt.strftime("%Y-%m-%d %H:%M")
                    
                    if now > expiry_dt:
                        status = "Expired"
                except:
                    expires = "Invalid date"
            
            tree.insert("", "end", values=(key_id, key_type, size, created, expires, status))
            
        if "private_key" in info and os.path.exists(os.path.join(KEY_DIRECTORY, info["private_key"])):
            key_type = "Private"
            size = info.get("bit_length", "Unknown")
            created = info.get("created", "Unknown")
            
            # Format the creation time
            if created != "Unknown":
                try:
                    created_dt = datetime.datetime.fromisoformat(created)
                    created = created_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            # Handle expiry
            expires = info.get("expires", "Never")
            status = "Valid"
            
            if expires != "Never":
                try:
                    expiry_dt = datetime.datetime.fromisoformat(expires)
                    expires = expiry_dt.strftime("%Y-%m-%d %H:%M")
                    
                    if now > expiry_dt:
                        status = "Expired"
                except:
                    expires = "Invalid date"
            
            tree.insert("", "end", values=(key_id, key_type, size, created, expires, status))
    
    # Then, handle legacy keys without metadata
    for key_file in key_files:
        if key_file == "public.pem":
            key_id = "legacy"
            key_type = "Public"
            size = "Unknown"
            created = "Unknown"
            expires = "Never"
            status = "Legacy"
            
            # Check if we haven't already added this from metadata
            if not any(tree.item(item, "values")[0] == key_id and tree.item(item, "values")[1] == key_type 
                      for item in tree.get_children()):
                tree.insert("", "end", values=(key_id, key_type, size, created, expires, status))
                
        elif key_file == "private.pem":
            key_id = "legacy"
            key_type = "Private"
            size = "Unknown"
            created = "Unknown"
            expires = "Never"
            status = "Legacy"
            
            # Check if we haven't already added this from metadata
            if not any(tree.item(item, "values")[0] == key_id and tree.item(item, "values")[1] == key_type 
                      for item in tree.get_children()):
                tree.insert("", "end", values=(key_id, key_type, size, created, expires, status))
    
    # Add action buttons
    button_frame = ttk.Frame(key_window, padding=10)
    button_frame.pack(fill="x")
    
    ttk.Button(button_frame, text="Close", command=key_window.destroy).pack(side="right", padx=5)
    
    key_window.transient(key_window.master)
    key_window.grab_set()
    key_window.wait_window()


def show_security_info():
    info_window = tk.Toplevel()
    info_window.title("Security Information")
    info_window.geometry("600x450")
    
    info_text = ttk.Label(info_window, text="""Asymmetric Encryption Security Features:
    
1. Key Management:
   - RSA key pairs with selectable key lengths (2048-4096 bits)
   - Password protection for private keys
   - Key expiration dates
   - Unique key IDs for tracking
   - Key metadata storage

2. File Encryption:
   - Hybrid encryption (RSA + AES-256-GCM)
   - Authenticated encryption with integrity protection
   - Multiple integrity checks (GCM tag, HMAC, file hash)
   - Tamper detection
   - Detailed encryption metadata
   - Audit logging

3. Digital Signatures:
   - RSA-PSS signatures for file authenticity
   - SHA-256 hashing
   - Signature verification
   - Signature metadata with timestamps

4. Security Best Practices:
   - Use 3072 or 4096 bit RSA keys for long-term security
   - Protect private keys with strong passwords
   - Set appropriate key expiration dates
   - Verify signatures before using downloaded files
   - Keep your private keys secure

The security features in this application follow current cryptographic best practices
and standards, but no software can guarantee absolute security. Always use additional
security measures for highly sensitive data.
    """, justify="left", wraplength=580)
    info_text.pack(padx=10, pady=10, expand=True, fill="both")
    
    ttk.Button(info_window, text="Close", command=info_window.destroy).pack(pady=10)
    
    info_window.transient(info_window.master)
    info_window.grab_set()
    info_window.wait_window()


def asymmetric_gui():
    root = tk.Tk()
    root.title("Advanced Asymmetric Cryptography Tool")
    style = Style(theme='superhero')

    root.geometry("600x480")
    
    main_frame = ttk.Frame(root, padding=20)
    main_frame.pack(fill="both", expand=True)
    
    # Key Management Section
    key_frame = ttk.LabelFrame(main_frame, text="Key Management")
    key_frame.pack(fill="x", pady=10)
    
    # Key size selection
    size_frame = ttk.Frame(key_frame)
    size_frame.pack(fill="x", pady=5)
    
    ttk.Label(size_frame, text="Key Size:").pack(side="left", padx=5)
    
    key_size_var = tk.IntVar(value=3072)
    key_sizes = [(2048, "2048 bits"), (3072, "3072 bits"), (4096, "4096 bits")]
    
    for size, label in key_sizes:
        ttk.Radiobutton(size_frame, text=label, variable=key_size_var, value=size).pack(side="left", padx=10)
    
    # Generate key button
    btn_generate_keys = ttk.Button(
        key_frame, 
        text="Generate New Keypair", 
        command=lambda: generate_keypair(key_size_var.get()),
        style="primary.TButton"
    )
    btn_generate_keys.pack(fill="x", pady=5)
    
    # Key management button
    btn_manage_keys = ttk.Button(
        key_frame,
        text="List/Manage Keys",
        command=list_keys,
    )
    btn_manage_keys.pack(fill="x", pady=5)
    
    # File Encryption Section
    encrypt_frame = ttk.LabelFrame(main_frame, text="File Encryption & Decryption")
    encrypt_frame.pack(fill="x", pady=10)
    
    btn_encrypt = ttk.Button(
        encrypt_frame, 
        text="Encrypt File", 
        command=on_encrypt,
        style="success.TButton"
    )
    btn_encrypt.pack(fill="x", pady=5)
    
    btn_decrypt = ttk.Button(
        encrypt_frame, 
        text="Decrypt File", 
        command=on_decrypt,
        style="info.TButton"
    )
    btn_decrypt.pack(fill="x", pady=5)
    
    # Digital Signature Section
    signature_frame = ttk.LabelFrame(main_frame, text="Digital Signatures")
    signature_frame.pack(fill="x", pady=10)
    
    btn_sign = ttk.Button(
        signature_frame,
        text="Sign File",
        command=on_sign,
        style="success.TButton"
    )
    btn_sign.pack(fill="x", pady=5)
    
    btn_verify = ttk.Button(
        signature_frame,
        text="Verify Signature",
        command=on_verify,
        style="info.TButton"
    )
    btn_verify.pack(fill="x", pady=5)
    
    # Security Info Button
    btn_security_info = ttk.Button(
        main_frame,
        text="Security Information",
        command=show_security_info,
        style="secondary.Outline.TButton"
    )
    btn_security_info.pack(fill="x", pady=10)

    # Add status bar at the bottom
    status_var = tk.StringVar(value="Ready")
    status_bar = ttk.Label(root, textvariable=status_var, relief="sunken", anchor="w")
    status_bar.pack(side="bottom", fill="x")

    root.mainloop()


if __name__ == "__main__":
    asymmetric_gui()

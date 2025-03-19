"""
Symmetric encryption module for the security application.
This module provides functions for symmetric encryption and decryption.
"""

import os
import logging
import datetime
import hashlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from tkinter import messagebox


# Set up logging
logger = logging.getLogger(__name__)


def open_and_read_file(filename):
    """
    Read a file as binary data.
    
    Args:
        filename (str): Path to the file
        
    Returns:
        bytes: File contents
    """
    try:
        with open(filename, "rb") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {filename}: {str(e)}")
        raise


def save_file(filename, data):
    """
    Save binary data to a file.
    
    Args:
        filename (str): Path to save the file
        data (bytes): Data to save
    """
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.info(f"File saved: {filename}")
    except Exception as e:
        logger.error(f"Error saving file {filename}: {str(e)}")
        raise


def init_cipher(key, mode, counter=None, iv=None, nonce=None):
    """
    Initialize an AES cipher object based on the encryption mode.
    
    Args:
        key (bytes): The encryption key
        mode (int): The AES mode (AES.MODE_*)
        counter (Counter, optional): Counter for CTR mode
        iv (bytes, optional): Initialization vector for CBC mode
        nonce (bytes, optional): Nonce for GCM mode
        
    Returns:
        Cipher: Initialized AES cipher object
    """
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


def create_log_file(log_file, mode_name, operation, source_file, output_file):
    """
    Create a log file for encryption/decryption operations.
    
    Args:
        log_file (str): Path to the log file
        mode_name (str): Encryption mode name
        operation (str): "Encryption" or "Decryption"
        source_file (str): Path to the source file
        output_file (str): Path to the output file
    """
    try:
        with open(log_file, "w") as log:
            log.write(f"{operation} mode: {mode_name}\n")
            log.write(f"Source file: {source_file}\n")
            log.write(f"Output file: {output_file}\n")
            log.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
        logger.info(f"Log file created: {log_file}")
    except Exception as e:
        logger.error(f"Failed to create log file {log_file}: {str(e)}")


def encrypt_file(cipher, read_filename, save_filename, mode, nonce=None, iv=None):
    """
    Encrypt a file using the specified AES mode.
    
    Args:
        cipher (Cipher): Initialized AES cipher object
        read_filename (str): Path to the file to encrypt
        save_filename (str): Path to save the encrypted file
        mode (int): The AES mode (AES.MODE_*)
        nonce (bytes, optional): Nonce for CTR or GCM mode
        iv (bytes, optional): Initialization vector for CBC mode
        
    Returns:
        bool: True if encryption was successful, False otherwise
    """
    try:
        # Read the input file
        block = open_and_read_file(read_filename)
        
        # Split the file into header and body (assuming header is 54 bytes)
        header = block[:54]
        body = block[54:]
        
        # Determine mode name for logging
        mode_names = {
            AES.MODE_ECB: "ECB",
            AES.MODE_CBC: "CBC",
            AES.MODE_CTR: "CTR",
            AES.MODE_GCM: "GCM"
        }
        mode_name = mode_names.get(mode, "Unknown")
        
        # Create log file
        log_file = f"{save_filename}.log"
        create_log_file(log_file, mode_name, "Encryption", read_filename, save_filename)
        
        # Encrypt based on mode
        if mode == AES.MODE_CTR:
            ciphertext = cipher.encrypt(body)
            result = header + nonce + ciphertext
        elif mode == AES.MODE_CBC:
            padded_body = pad(body, AES.block_size)
            ciphertext = cipher.encrypt(padded_body)
            result = header + iv + ciphertext
        elif mode == AES.MODE_GCM:
            ciphertext, tag = cipher.encrypt_and_digest(body)
            result = header + nonce + tag + ciphertext
        else:  # AES.MODE_ECB
            padded_body = pad(body, AES.block_size)
            ciphertext = cipher.encrypt(padded_body)
            result = header + ciphertext
        
        # Create a checksum of the encrypted data for integrity verification
        checksum = hashlib.sha256(result).digest()
        with open(f"{save_filename}.checksum", "wb") as f:
            f.write(checksum)
            logger.info(f"Checksum created for {save_filename}")
        
        # Save the encrypted file
        save_file(save_filename, result)
        logger.info(f"File encrypted successfully: {save_filename}")
        
        return True
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        return False


def decrypt_file(cipher, read_filename, decrypted_filename, mode, key):
    """
    Decrypt a file using the specified AES mode.
    
    Args:
        cipher (Cipher): Initialized AES cipher object
        read_filename (str): Path to the encrypted file
        decrypted_filename (str): Path to save the decrypted file
        mode (int): The AES mode (AES.MODE_*)
        key (bytes): The encryption key
        
    Returns:
        bool: True if decryption was successful, False otherwise
    """
    try:
        # Read the encrypted file
        block = open_and_read_file(read_filename)
        
        # Extract header (always 54 bytes)
        header = block[:54]
        
        # Verify file integrity with checksum if available
        checksum_file = f"{read_filename}.checksum"
        if os.path.exists(checksum_file):
            with open(checksum_file, "rb") as f:
                stored_checksum = f.read()
            
            calculated_checksum = hashlib.sha256(block).digest()
            if calculated_checksum != stored_checksum:
                logger.warning(f"Checksum verification failed for {read_filename}")
                messagebox.showwarning(
                    "Security Warning", "File checksum does not match! The file may have been tampered with."
                )
        
        # Determine mode name for logging
        mode_names = {
            AES.MODE_ECB: "ECB",
            AES.MODE_CBC: "CBC",
            AES.MODE_CTR: "CTR",
            AES.MODE_GCM: "GCM"
        }
        mode_name = mode_names.get(mode, "Unknown")
        
        # Decrypt based on mode
        if mode == AES.MODE_CTR:
            nonce = block[54:62]  # Extract the nonce (8 bytes)
            encrypted_data = block[62:]  # The rest is encrypted data
            ctr = Counter.new(64, prefix=nonce)
            cipher = AES.new(key, mode, counter=ctr)  # Re-initialize cipher with correct counter
            decrypted_body = cipher.decrypt(encrypted_data)
        elif mode == AES.MODE_CBC:
            iv = block[54:70]  # Extract the IV (16 bytes)
            encrypted_data = block[70:]
            cipher = AES.new(key, mode, iv=iv)  # Re-initialize cipher with correct IV
            decrypted_body = cipher.decrypt(encrypted_data)
            decrypted_body = unpad(decrypted_body, AES.block_size)
        elif mode == AES.MODE_GCM:
            nonce = block[54:70]  # Extract the nonce (16 bytes)
            tag = block[70:86]  # Extract the tag (16 bytes)
            encrypted_data = block[86:]
            cipher = AES.new(key, mode, nonce=nonce)
            try:
                decrypted_body = cipher.decrypt_and_verify(encrypted_data, tag)
            except ValueError as e:
                logger.error(f"Authentication failed: {str(e)}")
                messagebox.showerror("Security Error", "Authentication failed! The file has been tampered with.")
                return False
        else:  # AES.MODE_ECB
            encrypted_data = block[54:]
            decrypted_body = cipher.decrypt(encrypted_data)
            decrypted_body = unpad(decrypted_body, AES.block_size)
        
        # Combine header and decrypted body
        result = header + decrypted_body
        
        # Save the decrypted file
        save_file(decrypted_filename, result)
        logger.info(f"File decrypted successfully: {decrypted_filename}")
        
        # Log decryption information for security audit
        log_file = f"{decrypted_filename}.log"
        create_log_file(log_file, mode_name, "Decryption", read_filename, decrypted_filename)
        
        return True
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return False
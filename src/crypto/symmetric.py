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
        # Ensure the directory exists
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            logger.info(f"Created directory: {directory}")
        
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
        # Create directory for log file if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
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
        
        # Check file size
        logger.info(f"Input file size: {len(block)} bytes")
        
        # Split the file into header and body (assuming header is 54 bytes)
        # If file is smaller than 54 bytes, use empty header to avoid errors
        if len(block) < 54:
            logger.warning(f"File size ({len(block)} bytes) is less than expected header size (54 bytes)")
            header = b''
            body = block
        else:
            header = block[:54]
            body = block[54:]
            
        logger.info(f"Header size: {len(header)} bytes, Body size: {len(body)} bytes")
        
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
            # Ensure body is properly padded for AES block size
            padded_body = pad(body, AES.block_size)
            logger.info(f"ECB mode - padded body length: {len(padded_body)} bytes (should be multiple of {AES.block_size})")
            ciphertext = cipher.encrypt(padded_body)
            logger.info(f"ECB mode - ciphertext length: {len(ciphertext)} bytes")
            result = header + ciphertext
        
        # Create a checksum of the encrypted data for integrity verification
        checksum = hashlib.sha256(result).digest()
        checksum_file = f"{save_filename}.checksum"
        
        # Ensure the directory for the checksum file exists
        checksum_dir = os.path.dirname(checksum_file)
        if checksum_dir and not os.path.exists(checksum_dir):
            os.makedirs(checksum_dir, exist_ok=True)
            
        with open(checksum_file, "wb") as f:
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
        
        # Log file size for debugging
        logger.info(f"Encrypted file size: {len(block)} bytes")
        
        # Extract header (normally 54 bytes, but handle smaller files)
        if len(block) < 54:
            logger.warning(f"File size ({len(block)} bytes) is less than expected header size (54 bytes)")
            header = b''
        else:
            header = block[:54]
            
        logger.info(f"Header size: {len(header)} bytes")
        
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
        header_size = len(header)
        offset = header_size if header_size > 0 else 0
        
        if mode == AES.MODE_CTR:
            # Handle different header sizes
            if offset == 0:
                # No header - assume first 8 bytes are nonce
                if len(block) < 8:
                    logger.error("File too small to contain nonce data")
                    messagebox.showerror("Error", "File too small to contain required encryption metadata")
                    return False
                    
                nonce = block[:8]  # First 8 bytes are nonce
                encrypted_data = block[8:]  # The rest is encrypted data
            else:
                nonce = block[offset:offset+8]  # Extract the nonce (8 bytes)
                encrypted_data = block[offset+8:]  # The rest is encrypted data
                
            logger.info(f"CTR mode - nonce size: {len(nonce)} bytes, encrypted data: {len(encrypted_data)} bytes")
            ctr = Counter.new(64, prefix=nonce)
            cipher = AES.new(key, mode, counter=ctr)  # Re-initialize cipher with correct counter
            decrypted_body = cipher.decrypt(encrypted_data)
            
        elif mode == AES.MODE_CBC:
            # Handle different header sizes
            if offset == 0:
                # No header - assume first 16 bytes are IV
                if len(block) < 16:
                    logger.error("File too small to contain IV data")
                    messagebox.showerror("Error", "File too small to contain required encryption metadata")
                    return False
                    
                iv = block[:16]  # First 16 bytes are IV
                encrypted_data = block[16:]  # The rest is encrypted data
            else:
                iv = block[offset:offset+16]  # Extract the IV (16 bytes)
                encrypted_data = block[offset+16:]
                
            logger.info(f"CBC mode - IV size: {len(iv)} bytes, encrypted data: {len(encrypted_data)} bytes")
            cipher = AES.new(key, mode, iv=iv)  # Re-initialize cipher with correct IV
            
            try:
                decrypted_body = cipher.decrypt(encrypted_data)
                decrypted_body = unpad(decrypted_body, AES.block_size)
            except ValueError as e:
                logger.warning(f"CBC unpadding error: {str(e)}")
                # Try without unpadding if it fails
                decrypted_body = cipher.decrypt(encrypted_data)
                
        elif mode == AES.MODE_GCM:
            # Handle different header sizes
            if offset == 0:
                # No header - assume first 16 bytes are nonce, next 16 are tag
                if len(block) < 32:
                    logger.error("File too small to contain GCM nonce and tag data")
                    messagebox.showerror("Error", "File too small to contain required encryption metadata")
                    return False
                    
                nonce = block[:16]  # First 16 bytes are nonce
                tag = block[16:32]  # Next 16 bytes are tag
                encrypted_data = block[32:]  # The rest is encrypted data
            else:
                nonce = block[offset:offset+16]  # Extract the nonce (16 bytes)
                tag = block[offset+16:offset+32]  # Extract the tag (16 bytes)
                encrypted_data = block[offset+32:]
                
            logger.info(f"GCM mode - nonce: {len(nonce)} bytes, tag: {len(tag)} bytes, data: {len(encrypted_data)} bytes")
            cipher = AES.new(key, mode, nonce=nonce)
            
            try:
                decrypted_body = cipher.decrypt_and_verify(encrypted_data, tag)
            except ValueError as e:
                logger.error(f"Authentication failed: {str(e)}")
                messagebox.showerror("Security Error", "Authentication failed! The file has been tampered with.")
                return False
        else:  # AES.MODE_ECB
            # Extract encrypted data based on header size
            if len(header) == 0:
                encrypted_data = block  # Use entire block if no header
            else:
                encrypted_data = block[54:]  # Skip 54-byte header
                
            logger.info(f"ECB mode - encrypted data length: {len(encrypted_data)} bytes")
            
            # Check if the data length is a multiple of block size
            if len(encrypted_data) % AES.block_size != 0:
                logger.warning(f"Data length ({len(encrypted_data)}) is not a multiple of block size ({AES.block_size})")
                # Pad the data to a multiple of block size
                padding_needed = AES.block_size - (len(encrypted_data) % AES.block_size)
                encrypted_data = encrypted_data + (b'\0' * padding_needed)
                logger.info(f"Added {padding_needed} bytes of padding for decryption")
            
            try:
                decrypted_body = cipher.decrypt(encrypted_data)
                logger.info(f"Decryption successful, attempting to unpad")
                decrypted_body = unpad(decrypted_body, AES.block_size)
            except ValueError as e:
                logger.warning(f"Unpadding error: {str(e)}. Trying to continue without unpadding.")
                # If unpadding fails, we'll use the raw decrypted data
                decrypted_body = cipher.decrypt(encrypted_data)
                # If unpadding fails, we'll use the decrypted data as is
        
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
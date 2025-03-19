"""
Key management module for the security application.
This module provides functions for managing encryption keys.
"""

import os
import logging
from pathlib import Path
import hashlib
import datetime

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from tkinter import messagebox, simpledialog, Toplevel, StringVar, Entry, Button, Label


# Constants
KEY_DIR = Path("keys")
SECRET_KEY_PATH = KEY_DIR / "secret.key"
SALT_PATH = KEY_DIR / "salt"
CONFIG_PATH = Path("config")

# Set up logging
logger = logging.getLogger(__name__)


def ensure_key_directory():
    """Ensure the key directory exists"""
    KEY_DIR.mkdir(exist_ok=True)


def validate_password(password, confirm_password=None):
    """
    Validate password strength and matching.
    
    Args:
        password (str): The password to validate
        confirm_password (str, optional): Confirmation password to match
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    # Check for complexity requirements
    has_number = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)
    
    if not (has_number and has_upper and has_lower):
        return False, "Password must contain at least one number, one uppercase letter, and one lowercase letter"
    
    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match"
        
    return True, ""


def generate_key(parent_window, key_size=32):
    """
    Generate an encryption key based on a user password.
    
    Args:
        parent_window: The parent Tkinter window
        key_size (int): Size of the key in bytes (default is 32 for AES-256)
        
    Returns:
        bool: True if key was successfully generated, False otherwise
    """
    try:
        ensure_key_directory()
        
        # Generate a random salt
        salt = get_random_bytes(16)
        with open(SALT_PATH, "wb") as salt_file:
            salt_file.write(salt)
            logger.info(f"Salt written to {SALT_PATH}")
        
        # Create password input dialog
        password_window = Toplevel(parent_window)
        password_window.title("Password Protection")
        password_window.geometry("400x200")
        password_window.transient(parent_window)
        password_window.grab_set()
        
        password_var = StringVar()
        confirm_var = StringVar()
        error_var = StringVar()
        
        Label(password_window, text="Enter password:").pack(pady=5)
        password_entry = Entry(password_window, show="*", textvariable=password_var, width=30)
        password_entry.pack(pady=5)
        
        Label(password_window, text="Confirm password:").pack(pady=5)
        confirm_entry = Entry(password_window, show="*", textvariable=confirm_var, width=30)
        confirm_entry.pack(pady=5)
        
        error_label = Label(password_window, textvariable=error_var, fg="red", wraplength=350)
        error_label.pack(pady=5)
        
        result = [False]  # Use a list to store result as a mutable object
        
        def submit_password():
            password = password_var.get()
            confirm = confirm_var.get()
            
            # Validate password
            is_valid, error_message = validate_password(password, confirm)
            if not is_valid:
                error_var.set(error_message)
                return
            
            # Generate key using PBKDF2
            try:
                password_bytes = password.encode()
                key = PBKDF2(password_bytes, salt, dkLen=key_size, count=1000000)
                
                # Save the key
                save_key(key)
                
                # Save key size to config
                with open(CONFIG_PATH, "w") as config:
                    config.write(f"KEY_SIZE={key_size}\n")
                    config.write(f"KEY_CREATED={datetime.datetime.now().isoformat()}\n")
                    
                logger.info(f"Key generated successfully with size {key_size}")
                messagebox.showinfo("Success", "Key generated successfully!")
                result[0] = True
                password_window.destroy()
                
            except Exception as e:
                error_message = f"Failed to generate key: {str(e)}"
                logger.error(error_message)
                error_var.set(error_message)
        
        Button(password_window, text="Generate Key", command=submit_password).pack(pady=10)
        
        # Focus the password field
        password_entry.focus_set()
        
        # Wait for window to close
        password_window.wait_window()
        return result[0]
        
    except Exception as e:
        error_message = f"Failed to generate key: {str(e)}"
        logger.error(error_message)
        messagebox.showerror("Error", error_message)
        return False


def save_key(key):
    """
    Save the encryption key to file.
    
    Args:
        key (bytes): The key to save
    """
    try:
        ensure_key_directory()
        with open(SECRET_KEY_PATH, "wb") as key_file:
            key_file.write(key)
        logger.info(f"Key saved to {SECRET_KEY_PATH}")
        
        # Create a hash of the key for verification purposes
        key_hash = hashlib.sha256(key).hexdigest()
        with open(KEY_DIR / "key.hash", "w") as hash_file:
            hash_file.write(key_hash)
            
    except Exception as e:
        logger.error(f"Failed to save key: {str(e)}")
        raise


def load_key(password=None):
    """
    Load the encryption key from file.
    
    Args:
        password (str, optional): Password to derive the key. If None, will prompt user.
        
    Returns:
        bytes: The loaded key, or None if loading failed
    """
    try:
        if not all(p.exists() for p in [SECRET_KEY_PATH, SALT_PATH]):
            logger.error("Key files not found")
            messagebox.showerror("Error", "Key files not found. Please generate a key first.")
            return None
            
        if password is None:
            password = simpledialog.askstring("Password", "Enter key password:", show="*")
            if not password:
                return None
        
        # Load salt
        with open(SALT_PATH, "rb") as salt_file:
            salt = salt_file.read()
        
        # Get key size from config
        key_size = 32  # Default to AES-256
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as config:
                for line in config:
                    if line.startswith("KEY_SIZE="):
                        key_size = int(line.strip().split("=")[1])
                        break
        
        # Derive key from password and salt
        derived_key = PBKDF2(password.encode(), salt, dkLen=key_size, count=1000000)
        
        # Load stored key for comparison
        with open(SECRET_KEY_PATH, "rb") as key_file:
            stored_key = key_file.read()
        
        # Verify key
        if derived_key == stored_key:
            logger.info("Key loaded successfully")
            return derived_key
        else:
            logger.warning("Incorrect password provided")
            messagebox.showerror("Error", "Incorrect password")
            return None
            
    except FileNotFoundError as e:
        logger.error(f"Key file not found: {str(e)}")
        messagebox.showerror("Error", f"Key file not found: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Failed to load key: {str(e)}")
        messagebox.showerror("Error", f"Failed to load key: {str(e)}")
        return None
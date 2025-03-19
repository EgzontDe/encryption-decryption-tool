"""
Main application file for the encryption security tool.
"""

import os
import sys
import tkinter as tk
import logging
from pathlib import Path

# Import from our reorganized modules
from src.crypto.key_manager import generate_key, load_key
from src.crypto.symmetric import init_cipher, encrypt_file, decrypt_file
from src.crypto.utils import open_file, setup_logging, get_app_config, save_app_config
from src.gui.launcher import launch_launcher
from src.utils.file_manager import ensure_directories

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

def main():
    """Main entry point for the application"""
    # Ensure necessary directories exist
    ensure_directories()
    
    # Check if launcher should be shown
    if len(sys.argv) > 1 and sys.argv[1] == "--launcher":
        launch_launcher()
        return
    
    # Otherwise launch symmetric encryption GUI
    from src.gui.encryption_gui import main_gui
    main_gui()

if __name__ == "__main__":
    main()
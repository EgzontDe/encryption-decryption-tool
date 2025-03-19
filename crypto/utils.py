"""
Utility functions for the security application.
"""

import os
import sys
import logging
import subprocess
from pathlib import Path


# Set up logging
logger = logging.getLogger(__name__)


def setup_logging(log_level=logging.INFO):
    """
    Set up logging for the application.
    
    Args:
        log_level: Logging level (default: INFO)
    """
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging to file
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "security_app.log"),
            logging.StreamHandler()
        ]
    )


def open_file(filename):
    """
    Open a file with the default system application.
    
    Args:
        filename (str): Path to the file
    """
    try:
        if sys.platform == "win32":
            os.startfile(filename)
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.call([opener, filename])
        logger.info(f"Opened file: {filename}")
    except Exception as e:
        logger.error(f"Failed to open file {filename}: {str(e)}")


def validate_file_path(file_path):
    """
    Validate if a file path exists.
    
    Args:
        file_path (str): Path to validate
        
    Returns:
        bool: True if the file exists, False otherwise
    """
    path = Path(file_path)
    return path.exists() and path.is_file()


def get_app_config():
    """
    Load application configuration.
    
    Returns:
        dict: Configuration settings
    """
    config = {
        "key_size": 32,
        "key_created": None,
        "default_mode": "GCM"
    }
    
    config_path = Path("config")
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        if key == "KEY_SIZE":
                            config["key_size"] = int(value)
                        elif key == "KEY_CREATED":
                            config["key_created"] = value
                        elif key == "DEFAULT_MODE":
                            config["default_mode"] = value
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
    
    return config


def save_app_config(config):
    """
    Save application configuration.
    
    Args:
        config (dict): Configuration settings to save
    """
    try:
        with open("config", "w") as f:
            for key, value in config.items():
                if value is not None:
                    key_name = key.upper()
                    f.write(f"{key_name}={value}\n")
        logger.info("Configuration saved successfully")
    except Exception as e:
        logger.error(f"Failed to save configuration: {str(e)}")
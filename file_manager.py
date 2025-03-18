import os
import shutil
import datetime
import json
import hashlib
from pathlib import Path

# Default directories
DATA_DIR = "data"
ENCRYPTED_DIR = os.path.join(DATA_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(DATA_DIR, "decrypted")
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")
KEYS_DIR = "keys"
LOGS_DIR = os.path.join(DATA_DIR, "logs")
TEMP_DIR = os.path.join(DATA_DIR, "temp")

# Ensure all directories exist
def ensure_directories():
    """Make sure all required directories exist"""
    for directory in [DATA_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, SIGNATURES_DIR, KEYS_DIR, LOGS_DIR, TEMP_DIR]:
        os.makedirs(directory, exist_ok=True)

# File categorization
def categorize_file(file_path):
    """Determine what kind of file this is based on extension or content"""
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == ".enc":
        return "encrypted"
    elif ext == ".sig":
        return "signature"
    elif ext == ".pem":
        with open(file_path, 'rb') as f:
            content = f.read(100)  # Read the start of the file
            if b"PRIVATE" in content:
                return "private_key"
            elif b"PUBLIC" in content:
                return "public_key"
    elif ext == ".key":
        return "symmetric_key"
    elif ext == ".log":
        return "log"
    
    # Check if it's an encrypted file with metadata
    try:
        with open(file_path, 'rb') as f:
            header = f.read(5)
            if header == b'ENCV2':
                return "encrypted_v2"
    except (IOError, PermissionError):
        pass
        
    return "unknown"

# File management functions
def save_file(data, destination_dir=None, filename=None, category=None, create_metadata=True):
    """
    Save data to file with proper organization
    
    Args:
        data: The data to save (bytes or string)
        destination_dir: Optional directory to save in (default based on category)
        filename: Optional filename to use
        category: The type of file (encrypted, decrypted, signature, etc.)
        create_metadata: Whether to create a metadata file
        
    Returns:
        Tuple of (saved_path, metadata_path)
    """
    ensure_directories()
    
    # Determine the appropriate directory
    if destination_dir is None:
        if category == "encrypted":
            destination_dir = ENCRYPTED_DIR
        elif category == "decrypted":
            destination_dir = DECRYPTED_DIR
        elif category == "signature":
            destination_dir = SIGNATURES_DIR
        elif category in ("private_key", "public_key", "symmetric_key"):
            destination_dir = KEYS_DIR
        elif category == "log":
            destination_dir = LOGS_DIR
        else:
            destination_dir = DATA_DIR
    
    # Generate a filename if not provided
    if filename is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if category == "encrypted":
            filename = f"encrypted_{timestamp}.enc"
        elif category == "decrypted":
            filename = f"decrypted_{timestamp}.bin"
        elif category == "signature":
            filename = f"signature_{timestamp}.sig"
        elif category == "private_key":
            filename = f"private_{timestamp}.pem"
        elif category == "public_key":
            filename = f"public_{timestamp}.pem"
        elif category == "symmetric_key":
            filename = f"key_{timestamp}.key"
        elif category == "log":
            filename = f"log_{timestamp}.log"
        else:
            filename = f"file_{timestamp}.dat"
    
    # Ensure the destination directory exists
    os.makedirs(destination_dir, exist_ok=True)
    
    # Construct the full file path
    file_path = os.path.join(destination_dir, filename)
    
    # Write mode depends on data type
    write_mode = "wb" if isinstance(data, bytes) else "w"
    
    # Save the data
    with open(file_path, write_mode) as f:
        f.write(data)
    
    # Create metadata if requested
    metadata_path = None
    if create_metadata:
        metadata = {
            "filename": filename,
            "category": category,
            "timestamp": datetime.datetime.now().isoformat(),
            "size": len(data) if isinstance(data, bytes) else len(data.encode('utf-8')),
            "path": file_path,
            "checksum": hashlib.sha256(data if isinstance(data, bytes) else data.encode('utf-8')).hexdigest()
        }
        
        metadata_path = f"{file_path}.meta"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    return file_path, metadata_path

def load_file(file_path, as_bytes=True):
    """
    Load data from a file
    
    Args:
        file_path: Path to the file to load
        as_bytes: Whether to return bytes (True) or try to decode as string (False)
        
    Returns:
        File contents as bytes or string
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not as_bytes:
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                # Not a text file, return as bytes
                return data
        return data
    except Exception as e:
        raise IOError(f"Error loading file {file_path}: {str(e)}")

def list_files(directory=None, category=None, pattern=None):
    """
    List files with optional filtering
    
    Args:
        directory: Directory to search in (default: all managed directories)
        category: Filter by file category
        pattern: Filename pattern to match
        
    Returns:
        List of file paths matching criteria
    """
    ensure_directories()
    
    # Determine which directories to search
    if directory is not None:
        directories = [directory]
    else:
        if category == "encrypted":
            directories = [ENCRYPTED_DIR]
        elif category == "decrypted":
            directories = [DECRYPTED_DIR]
        elif category == "signature":
            directories = [SIGNATURES_DIR]
        elif category in ("private_key", "public_key", "symmetric_key"):
            directories = [KEYS_DIR]
        elif category == "log":
            directories = [LOGS_DIR]
        else:
            directories = [DATA_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, SIGNATURES_DIR, KEYS_DIR, LOGS_DIR]
    
    # Collect all files matching criteria
    result = []
    for directory in directories:
        if not os.path.exists(directory):
            continue
            
        for root, dirs, files in os.walk(directory):
            for filename in files:
                # Skip metadata files
                if filename.endswith('.meta'):
                    continue
                    
                # Skip files that don't match the pattern
                if pattern and not filename.lower().find(pattern.lower()) >= 0:
                    continue
                
                file_path = os.path.join(root, filename)
                
                # Filter by category if specified
                if category:
                    file_category = categorize_file(file_path)
                    if file_category != category:
                        continue
                
                result.append(file_path)
    
    # Sort by modification time (newest first)
    result.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return result

def move_file(source_path, destination_dir=None, new_filename=None):
    """
    Move a file to another directory with optional renaming
    
    Args:
        source_path: Path to the file to move
        destination_dir: Target directory (default: appropriate dir based on file type)
        new_filename: Optional new filename
        
    Returns:
        New file path
    """
    ensure_directories()
    
    # Determine the appropriate destination directory if not provided
    if destination_dir is None:
        category = categorize_file(source_path)
        if category == "encrypted":
            destination_dir = ENCRYPTED_DIR
        elif category == "decrypted":
            destination_dir = DECRYPTED_DIR
        elif category == "signature":
            destination_dir = SIGNATURES_DIR
        elif category in ("private_key", "public_key", "symmetric_key"):
            destination_dir = KEYS_DIR
        elif category == "log":
            destination_dir = LOGS_DIR
        else:
            destination_dir = DATA_DIR
    
    # Ensure the destination directory exists
    os.makedirs(destination_dir, exist_ok=True)
    
    # Determine the destination filename
    if new_filename is None:
        new_filename = os.path.basename(source_path)
    
    # Construct the destination path
    destination_path = os.path.join(destination_dir, new_filename)
    
    # Move the file
    shutil.move(source_path, destination_path)
    
    # If there's a metadata file, move it too
    meta_source = f"{source_path}.meta"
    if os.path.exists(meta_source):
        meta_dest = f"{destination_path}.meta"
        shutil.move(meta_source, meta_dest)
    
    return destination_path

def delete_file(file_path, delete_metadata=True):
    """
    Delete a file
    
    Args:
        file_path: Path to the file to delete
        delete_metadata: Whether to delete the associated metadata file
        
    Returns:
        True if successfully deleted
    """
    try:
        os.remove(file_path)
        
        # Delete metadata file if it exists and requested
        if delete_metadata:
            meta_path = f"{file_path}.meta"
            if os.path.exists(meta_path):
                os.remove(meta_path)
        
        return True
    except Exception as e:
        raise IOError(f"Error deleting file {file_path}: {str(e)}")

def get_file_info(file_path):
    """
    Get detailed information about a file
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with file information
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File does not exist: {file_path}")
        
        # Get basic file information
        stat = os.stat(file_path)
        
        # Read metadata if available
        metadata = {}
        meta_path = f"{file_path}.meta"
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r') as f:
                    metadata = json.load(f)
            except json.JSONDecodeError:
                pass
        
        # Calculate checksum if not in metadata
        checksum = metadata.get('checksum')
        if not checksum:
            try:
                with open(file_path, 'rb') as f:
                    checksum = hashlib.sha256(f.read()).hexdigest()
            except:
                checksum = "Could not compute"
        
        # Combine information
        info = {
            "path": file_path,
            "filename": os.path.basename(file_path),
            "directory": os.path.dirname(file_path),
            "size": stat.st_size,
            "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
            "category": categorize_file(file_path),
            "checksum": checksum,
            "has_metadata": os.path.exists(meta_path),
            **metadata
        }
        
        return info
    except Exception as e:
        raise IOError(f"Error getting file info for {file_path}: {str(e)}")

# Initialize directories when module is imported
ensure_directories()
# Advanced Encryption Toolkit

## Description

This advanced encryption toolkit, designed and implemented by Egzont Demiri, provides comprehensive tools for secure file encryption, decryption, and management. The application offers both symmetric and asymmetric encryption options with enhanced security features and an improved user interface.

## Enhanced Features

### Symmetric Encryption
- **Password-Protected Keys**: Keys are now protected with PBKDF2 key derivation
- **Multiple AES Modes**: Choose between ECB, CTR, CBC, and GCM modes
- **Flexible Key Sizes**: Support for AES-128, AES-192, and AES-256
- **File Integrity Verification**: SHA-256 checksums for encrypted files
- **Enhanced Tamper Detection**: Multiple integrity checks including HMAC and GCM authentication

### Asymmetric Encryption
- **Advanced Key Management**: Support for key expiration, password protection, and metadata
- **Digital Signatures**: RSA-PSS signatures for file authentication
- **Multiple Security Layers**: Hybrid encryption with RSA + AES-GCM
- **Improved File Format**: Versioned file format with embedded metadata

### File Management
- **Organized Directory Structure**: Files are organized by type (encrypted, decrypted, keys, signatures)
- **File Browser**: Dedicated file browser for managing encrypted files and keys
- **Metadata Support**: File categorization and tracking with metadata
- **Import/Export Capabilities**: Easy file importing and exporting

### Tampering Tools
- **Enhanced Tampering Tool**: GUI interface for educational tampering demonstrations
- **Multiple Tampering Methods**: Bit flipping, zeroing, incrementing, or randomization
- **Backup and Restore**: File backup before tampering

### Docker Support
- **Containerized Deployment**: Run the application in a Docker container
- **Volume Mounting**: Persistent storage for keys and encrypted files
- **Easy Setup**: Simple docker-compose configuration

## Requirements

### Standard Installation
- Python 3.10+
- tkinter
- ttkbootstrap
- pycryptodome
- sympy

To install the dependencies:
```sh
pip install -r requirements.txt
```

### Docker Installation
- Docker
- Docker Compose

## Installation

### Standard Installation
1. Clone the repository
2. Install the dependencies: `pip install -r requirements.txt`
3. Run the launcher: `python launcher.py`

### Docker Installation
1. Clone the repository
2. Build and start the container: `docker-compose up -d`
3. For X11 forwarding (Linux): `xhost +local:docker`

## Usage

### Launcher
Run `python launcher.py` to open the main launcher which provides access to all tools:
- Symmetric Encryption
- Asymmetric Encryption
- File Browser
- Tampering Tool

### Symmetric Encryption (AES)
- **Key Generation**: Generate a key with customizable size and password protection
- **Encryption Modes**: Choose from ECB, CTR, CBC, or GCM modes (GCM recommended)
- **File Encryption/Decryption**: Encrypt any file type with integrity protection

### Asymmetric Encryption (RSA)
- **Key Management**: Generate and manage RSA key pairs with metadata
- **File Encryption**: Encrypt files using hybrid encryption (RSA + AES)
- **Digital Signatures**: Sign files and verify signatures

### File Browser
- **File Management**: Browse, move, and manage encrypted files and keys
- **File Details**: View detailed information about files including checksums
- **Import/Export**: Import files into the managed directory structure

### Tampering Tool
- **Educational Tool**: Demonstrate tampering with encrypted files
- **Tampering Methods**: Choose from different tampering methods
- **GUI Interface**: User-friendly interface for tampering demonstrations

## Directory Structure

```
/
├── keys/              # Encryption keys
├── data/              # Data directory
│   ├── encrypted/     # Encrypted files
│   ├── decrypted/     # Decrypted files
│   ├── signatures/    # Digital signatures
│   └── logs/          # Operation logs
├── Dockerfile         # Docker configuration
├── docker-compose.yml # Docker Compose configuration
├── main.py            # Symmetric encryption app
├── asym.py            # Asymmetric encryption app
├── file_browser.py    # File management app
├── file_manager.py    # File management library
├── tamper_with_encryption.py # Tampering tool
└── launcher.py        # Main application launcher
```

## Docker Usage

The application can be run inside a Docker container for improved portability and isolation.

### Building and Starting
```sh
docker-compose up -d
```

### X11 Forwarding (for GUI)
For Linux:
```sh
xhost +local:docker
```

For Windows:
1. Install an X server like VcXsrv or Xming
2. Set the DISPLAY environment variable

## Security Features

- **Advanced Key Management**: Password-protected keys with metadata
- **Multiple Integrity Checks**: SHA-256 checksums, HMAC, GCM authentication tags
- **Authenticated Encryption**: GCM mode provides confidentiality and integrity
- **Hybrid Encryption**: RSA for key exchange, AES for data encryption
- **Digital Signatures**: RSA-PSS signatures for file authentication

## Important Notes

- This toolkit is designed for educational purposes and should not be used for sensitive data without additional review.
- For maximum security, use GCM mode for symmetric encryption and RSA-4096 for asymmetric keys.
- Always use strong passwords for key protection.
- The application automatically organizes files in the data directory.

## Troubleshooting

- **GUI not appearing in Docker**: Ensure X11 forwarding is properly configured
- **File permissions**: Ensure the application has write permissions to the keys and data directories
- **Decryption failures**: Verify you're using the correct key and encryption mode
- **Docker volume issues**: Check that volumes are properly mounted in docker-compose.yml

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- The pycryptodome project for providing the cryptographic library
- The creators of tkinter and ttkbootstrap for the GUI framework

Enjoy using the Advanced Encryption Toolkit responsibly!

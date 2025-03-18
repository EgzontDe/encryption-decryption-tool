# Encryption / Decryption by Egzont Demiri

## Description


This application, designed and implemented by Egzont Demiri for a project in Security at the University of Neuchatel

## Features

- **Key Generation**: Generates a 128-bit secret key.
- **Encryption Modes**: Choose between ECB and CTR modes for AES encryption.
- **File Encryption**: Encrypt `.bmp`  files with the click of a button and the chosen encryption mode.
- **File Decryption**: Decrypt files that were previously encrypted using this application, ensuring the correct encryption mode is selected.
- **Asymmetric Encryption Option**: A button that launches a separate frame for handling asymmetric encryption/decryption.
- **Auto File Handling**: The application automatically handles file opening and saving.
- **RSA Keypair Generation**: Generates a 2048-bit RSA key pair and stores them as `private.pem` and `public.pem` in the `keys` directory.
- **File Encryption**: Encrypts files using the public key and AES in GCM mode for the actual file data, storing the result in a `.enc` file.
- **File Decryption**: Decrypts `.enc` files using the private key, assuming they were encrypted using the corresponding public key.
- **Error Handling**: Displays error messages in cases like decryption failure due to file tampering.

## Requirements

- Python 3.x
- tkinter
- ttkbootstrap 
- pycryptodome
- sympy

To install the dependencies, use pip:
```sh
pip install tk
pip install ttkbootstrap
pip install pycryptodome
pip install sympy
```
# Usage

## Key Generation
When you  launch the app, You can generate a new secret key and IV by clicking the "Generate Key" The keys will be stored on your machine.

## Select Encryption Mode
Choose the AES mode (ECB or CTR) by  button.

## Encrypt/Decrypt Files
- To encrypt a file, click "Encrypt File," and select the .bmp file you wish to encrypt. The encrypted file is automatically saved in your directory.
- To decrypt a file, click "Decrypt File," and select the encrypted .bmp file. The decrypted file is automatically saved in the directory.

## Asymmetric Encryption/Decryption
By clicking the "Asymmetric Encryption/Decryption" button, you can run a separate frame handling asymmetric cryptographic
## Start the Application: Run the script to open the GUI.

## Generate RSA Keypair: 
Click the "Generate Keypair" button to create a new RSA key pair. The keys will be stored as public.pem and private.pem in the keys directory.

## Encrypt Files:
  - Click "Encrypt Message" and select the public key file (public.pem).
  - Choose a file to encrypt. The encrypted file will be saved with the .enc extension.

## Decrypt Files:
  - Click "Decrypt Message" and select the private key file (private.pem).
  - Choose the .enc file to decrypt. The decrypted file will be saved with a decrypted_ prefix.

## View Results
After encryption/decryption, the resulting file is automatically opened, and the status is displayed at the bottom of the application window.
# Encrypted File Tampering 

## Description

It allows users to modify a single byte within the ciphertext  of an encrypted file, while leaving the header, nonce, and tag intact.

## Usage

1. **Run the Script**: Execute the script with the following command-line syntax:

    ```sh
    python tamper_with_encryption.py [path_to_encrypted_file]
    ```

   Replace `[path_to_encrypted_file]` with the path to the encrypted file you want to tamper with.

2. **Tampering**: The script will attempt to flip one bit of the first byte of the ciphertext within the specified encrypted file.
3. **Checking** Then you can try to decrypt that file using the correct mode you have encrypted, If tampering is detected you'll get an error.
## Important Notes

- This Project is designed for educational purposes and should not be used for malicious activities.
- The specific byte and bit that are tampered with (byte 90, bit 0 in this example) may need to be adjusted

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

Enjoy using the Encrypted File Tampering Utility responsibly!

# Important Notes

- The application handles .bmp & .other formats files for encryption and decryption.
- Keys are saved in the "keys" folder in the application's directory.
- The application must be used for decryption with the correct AES mode that was used for encryption; otherwise, the decryption will fail.
- The utility is designed for educational purposes and demonstrates symmetric and asymmetric encryption/decryption.
# Troubleshooting

If you have any issues with the application, first ensure you have the latest versions of Python and the necessary packages installed. Verify that the "keys" folder exists in the same directory as the application. For decryption to work correctly, the correct AES mode must be selected, matching the mode used during encryption.

# License

This project is licensed under the MIT License. See the LICENSE file for details.

# Acknowledgments

- The pycryptodome project for providing the cryptographic library used in this application.
- The creators of tkinter and ttkbootstrap for providing the tools to create a user-friendly graphical interface.
Enjoy using the Encryption/Decryption tool!

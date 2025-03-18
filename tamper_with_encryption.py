import sys

def tamper_file(file_path):
    with open(file_path, 'rb') as file:
        data = bytearray(file.read())

    # Assuming a header of 54 bytes, nonce of 16 bytes, and tag of 16 bytes.
    # Adjust depending on your files
    data[90] = data[90] ^ 0x01  # Flipping one bit of the 1st byte of the ciphertext

    with open(file_path, 'wb') as file:
        file.write(data)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tamper_with_encryption.py [path_to_encrypted_file]")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        tamper_file(file_path)
        print(f"File tampered successfully: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

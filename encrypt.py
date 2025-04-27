import os
import hashlib
import math
import struct
import binascii
from typing import Dict


def extract_key_from_file(key_file_path: str) -> Dict[str, int]:
    """Extract key parameters from a key file."""
    key_data = {}
    try:
        with open(key_file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith('-----'):
                    continue
                if ':' in line:
                    key, value = line.strip().split(':', 1)
                    key_data[key] = int(value, 16)
        
        print(f"Extracted key parameters: {', '.join(key_data.keys())}")
        if 'n' in key_data:
            print(f"Modulus bit length: {key_data['n'].bit_length()}")
        
        # For public key, default e to 65537 if not present
        if 'e' not in key_data:
            print("No 'e' value found in key file. Defaulting to 65537 (0x10001)")
            key_data['e'] = 65537
        
        return key_data
    except Exception as e:
        print(f"Error extracting key from file: {e}")
        raise


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """Mask Generation Function 1 as defined in PKCS#1 v2.1."""
    hash_len = 32  # SHA-256 output length in bytes
    if mask_len > (2**32) * hash_len:
        raise ValueError("Mask too long")
    
    t = b""
    for counter in range(0, math.ceil(mask_len / hash_len)):
        c = counter.to_bytes(4, byteorder='big')
        t += sha256(seed + c)
    
    return t[:mask_len]


def xor_bytes(data: bytes, mask: bytes) -> bytes:
    """XOR two byte arrays."""
    if len(data) != len(mask):
        print(f"Warning: XOR input lengths differ: data={len(data)} bytes, mask={len(mask)} bytes")
    return bytes(a ^ b for a, b in zip(data, mask))


def int_to_bytes(n: int, length: int) -> bytes:
    """Convert an integer to a byte array of specified length."""
    try:
        return n.to_bytes(length, byteorder='big')
    except OverflowError as e:
        print(f"Error in int_to_bytes: {e}, n={n}, length={length}, n_bit_length={n.bit_length()}")
        raise


def bytes_to_int(b: bytes) -> int:
    """Convert a byte array to an integer."""
    return int.from_bytes(b, byteorder='big')


def rsa_encrypt(message: bytes, n: int, e: int) -> bytes:
    """Perform basic RSA encryption: c = m^e mod n"""
    m = bytes_to_int(message)
    if m >= n:
        print(f"Error: Message value ({m}) is larger than modulus ({n})")
        raise ValueError("Message too large")
    
    c = pow(m, e, n)
    byte_len = (n.bit_length() + 7) // 8
    return int_to_bytes(c, byte_len)


def oaep_pad(message: bytes, k: int, label: bytes = b"") -> bytes:
    """
    Apply OAEP padding to the message.
    k: length in bytes of the RSA modulus
    """
    hLen = 32  # SHA-256 hash length in bytes
    mLen = len(message)
    
    print(f"OAEP pad: message length={mLen}, k={k}, max message length={k - 2 * hLen - 2}")
    
    # Check if message is too long
    if mLen > k - 2 * hLen - 2:
        print(f"Error: Message too long for OAEP padding")
        raise ValueError("Message too long")
    
    # Compute label hash
    lHash = sha256(label)
    print(f"Label hash: {binascii.hexlify(lHash)}")
    
    # Generate padding string
    PS = b'\x00' * (k - mLen - 2 * hLen - 2)
    print(f"Padding string length: {len(PS)}")
    
    # Construct data block
    DB = lHash + PS + b'\x01' + message
    print(f"Data block length: {len(DB)}")
    
    # Generate random seed
    seed = os.urandom(hLen)
    print(f"Seed generated: {len(seed)} bytes")
    
    # Calculate mask for DB
    dbMask = mgf1(seed, k - hLen - 1)
    
    # XOR DB with dbMask
    maskedDB = xor_bytes(DB, dbMask)
    
    # Calculate mask for seed
    seedMask = mgf1(maskedDB, hLen)
    
    # XOR seed with seedMask
    maskedSeed = xor_bytes(seed, seedMask)
    
    # Construct the padded message
    padded = b'\x00' + maskedSeed + maskedDB
    print(f"Final padded message length: {len(padded)}")
    
    return padded


def encrypt_block(message: bytes, key: Dict[str, int]) -> bytes:
    """Encrypt a single block using RSA-OAEP."""
    try:
        n = key['n']
        e = key['e']
        
        k = (n.bit_length() + 7) // 8  # RSA modulus size in bytes
        print(f"RSA modulus size: {k} bytes")
        
        # Apply OAEP padding
        padded_message = oaep_pad(message, k)
        print(f"Message padded successfully, length: {len(padded_message)} bytes")
        
        # Apply RSA encryption
        encrypted = rsa_encrypt(padded_message, n, e)
        print(f"Block encrypted successfully, length: {len(encrypted)} bytes")
        
        return encrypted
    except Exception as e:
        print(f"Error in encrypt_block: {e}")
        raise


def encrypt_file(input_file_path: str, public_key_path: str, output_file_path: str) -> None:
    """
    Encrypt a file using RSA-OAEP.
    
    Args:
        input_file_path: Path to the plaintext file
        public_key_path: Path to the public key file
        output_file_path: Path to write the ciphertext file
    """
    print(f"\nEncrypting file: {input_file_path}")
    print(f"Using public key: {public_key_path}")
    print(f"Output will be written to: {output_file_path}")
    
    # Extract public key
    key = extract_key_from_file(public_key_path)
    n = key['n']
    
    # Calculate maximum message length for each block
    # For OAEP with SHA-256, the max data length is modulus_size - 2 * hash_size - 2
    k = (n.bit_length() + 7) // 8  # RSA modulus size in bytes
    hLen = 32  # SHA-256 hash length in bytes
    max_message_len = k - 2 * hLen - 2
    
    print(f"Maximum message length per block: {max_message_len} bytes")
    
    # Get file size
    file_size = os.path.getsize(input_file_path)
    print(f"Input file size: {file_size} bytes")
    
    block_count = 0
    
    # Process file in blocks
    with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
        while True:
            block = infile.read(max_message_len)
            if not block:
                print("End of file reached")
                break
            
            # Encrypt block
            encrypted_block = encrypt_block(block, key)
            
            # Write the length of the encrypted block followed by the block itself
            outfile.write(struct.pack('>I', len(encrypted_block)))
            outfile.write(encrypted_block)
            
            block_count += 1
    
    # Get output file size
    output_size = os.path.getsize(output_file_path)
    print(f"\nEncryption completed. {block_count} blocks processed.")
    print(f"Output file size: {output_size} bytes")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='RSA-OAEP Encryption')
    parser.add_argument('input_file', help='Path to the plaintext file')
    parser.add_argument('public_key', help='Path to the public key file')
    parser.add_argument('output_file', help='Path to write the ciphertext file')
    
    args = parser.parse_args()
    
    try:
        encrypt_file(args.input_file, args.public_key, args.output_file)
        print(f"\nFile encrypted successfully. Output written to {args.output_file}")
    except Exception as e:
        print(f"\nEncryption failed with error: {e}")
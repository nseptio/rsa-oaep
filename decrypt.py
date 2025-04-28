import hashlib
import math
import struct
import binascii
from typing import Dict, Optional


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
        min_len = min(len(data), len(mask))
        return bytes(a ^ b for a, b in zip(data[:min_len], mask[:min_len]))
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


def rsa_decrypt(ciphertext: bytes, n: int, d: int) -> bytes:
    """Perform basic RSA decryption: m = c^d mod n"""
    c = bytes_to_int(ciphertext)
    if c >= n:
        print(f"Warning: Ciphertext value ({c}) is larger than modulus ({n})")
        raise ValueError("Ciphertext too large")
    
    m = pow(c, d, n)
    byte_len = (n.bit_length() + 7) // 8
    
    try:
        return int_to_bytes(m, byte_len)
    except Exception as e:
        print(f"Error in RSA decrypt: {e}")
        raise


def oaep_unpad(padded_message: bytes, k: int, label: bytes = b"") -> Optional[bytes]:
    """
    Remove OAEP padding from the message.
    k: length in bytes of the RSA modulus
    Returns None if padding is invalid.
    """
    hLen = 32  # SHA-256 hash length in bytes
    
    print(f"First few bytes (hex): {binascii.hexlify(padded_message[:16])}")
    
    # Check if padded message has correct length
    if len(padded_message) != k:
        print(f"Error: Padded message length {len(padded_message)} doesn't match expected length {k}")
        return None
    
    # Check if first byte is 0x00
    if padded_message[0] != 0:
        print(f"Error: First byte is {padded_message[0]}, expected 0")
        return None
    
    # Separate parts of the padded message
    maskedSeed = padded_message[1:1+hLen]
    maskedDB = padded_message[1+hLen:]
    
    
    # Calculate seed mask
    seedMask = mgf1(maskedDB, hLen)
    
    # Recover seed
    seed = xor_bytes(maskedSeed, seedMask)
    
    # Calculate DB mask
    dbMask = mgf1(seed, k - hLen - 1)
    
    # Recover DB
    DB = xor_bytes(maskedDB, dbMask)
    
    # Compute label hash
    lHash = sha256(label)
    
    # Verify label hash
    if DB[:hLen] != lHash:
        print(f"Error: Label hash doesn't match")
        print(f"Expected: {binascii.hexlify(lHash)}")
        print(f"Got: {binascii.hexlify(DB[:hLen])}")
        return None
    
    
    # Find the index of the first 0x01 byte after lHash
    one_index = hLen
    zeros_count = 0
    
    while one_index < len(DB):
        if DB[one_index] == 0:
            one_index += 1
            zeros_count += 1
        elif DB[one_index] == 1:
            print(f"Found 0x01 separator at index {one_index} after {zeros_count} zeros")
            break
        else:
            print(f"Invalid padding byte {DB[one_index]} at index {one_index}")
            return None  # Invalid padding
    else:
        print("No 0x01 separator found")
        return None  # No 0x01 separator found
    
    # Extract the message
    message = DB[one_index + 1:]
    print(f"Extracted message length: {len(message)}")
    
    return message


def decrypt_block(ciphertext: bytes, key: Dict[str, int]) -> Optional[bytes]:
    """Decrypt a single block using RSA-OAEP."""
    try:
        n = key['n']
        d = key['d']
        
        print("Decrypting...")
        decrypted_padded = rsa_decrypt(ciphertext, n, d)
        
        k = (n.bit_length() + 7) // 8  # RSA modulus size in bytes
        
        # Remove OAEP padding
        return oaep_unpad(decrypted_padded, k)
    except Exception as e:
        print(f"Error in decrypt_block: {e}")
        raise


def decrypt_file(input_file_path: str, private_key_path: str, output_file_path: str) -> None:
    """
    Decrypt a file using RSA-OAEP.
    
    Args:
        input_file_path: Path to the ciphertext file
        private_key_path: Path to the private key file
        output_file_path: Path to write the plaintext file
    """
    print(f"\nDecrypting file: {input_file_path}")
    print(f"Using private key: {private_key_path}")
    print(f"Output will be written to: {output_file_path}")
    
    # Extract private key
    key = extract_key_from_file(private_key_path)
    
    block_count = 0
    
    # Process file in blocks
    with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
        while True:
            # Read the length of the next encrypted block
            length_bytes = infile.read(4)
            if not length_bytes or len(length_bytes) < 4:
                print("End of file reached")
                break
            
            block_length = struct.unpack('>I', length_bytes)[0]
            
            # Read the encrypted block
            encrypted_block = infile.read(block_length)
            if not encrypted_block or len(encrypted_block) != block_length:
                print(f"Error: Expected {block_length} bytes but got {len(encrypted_block)}")
                raise ValueError("Corrupted input file")
            
            # Decrypt block
            decrypted_block = decrypt_block(encrypted_block, key)
            
            if decrypted_block is None:
                print("Decryption failed: Invalid padding")
                raise ValueError("Decryption failed: Invalid padding")
            
            # Write the decrypted block
            outfile.write(decrypted_block)
            block_count += 1
    
    print(f"\nDecryption completed. {block_count} blocks processed.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='RSA-OAEP Decryption')
    parser.add_argument('input_file', help='Path to the ciphertext file')
    parser.add_argument('private_key', help='Path to the private key file')
    parser.add_argument('output_file', help='Path to write the plaintext file')
    
    args = parser.parse_args()
    
    try:
        decrypt_file(args.input_file, args.private_key, args.output_file)
        print(f"\nFile decrypted successfully. Output written to {args.output_file}")
    except Exception as e:
        print(f"\nDecryption failed with error: {e}")
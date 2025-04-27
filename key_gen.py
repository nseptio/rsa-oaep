from typing import Tuple, Dict
import random

def miller_rabin_test(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test
    
    Args:
        n: The number to test for primality
        k: Number of test rounds
        
    Returns:
        bool: True if n is probably prime, False if n is composite
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """
    Generate a prime number of the specified bit length
    
    Args:
        bits: The bit length of the prime number
        
    Returns:
        int: A prime number of the specified bit length
    """
    while True:
        # Generate a random odd number with the specified bit length
        p = random.getrandbits(bits)
        # Set the most significant bit to ensure the bit length
        p |= (1 << bits - 1)
        # Set the least significant bit to ensure it's odd
        p |= 1
        
        # Check if it's prime using Miller-Rabin test
        if miller_rabin_test(p):
            return p

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm to find gcd(a, b) and coefficients x, y such that ax + by = gcd(a, b)
    
    Args:
        a: First number
        b: Second number
        
    Returns:
        Tuple[int, int, int]: (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y

def mod_inverse(a: int, m: int) -> int:
    """
    Find the modular multiplicative inverse of a modulo m
    
    Args:
        a: Number to find the inverse for
        m: Modulus
        
    Returns:
        int: The modular multiplicative inverse
    """
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m

def generate_rsa_keypair(bits: int = 2048) -> Tuple[Dict[str, int], Dict[str, int]]:
    """
    Generate RSA key pair
    
    Args:
        bits: The bit length for the RSA modulus (n)
        
    Returns:
        Tuple[Dict[str, int], Dict[str, int]]: (public_key, private_key)
    """
    # Generate two prime numbers of half the bit length
    p_bits = bits // 2
    q_bits = bits - p_bits
    
    p = generate_prime(p_bits)
    q = generate_prime(q_bits)
    
    # Calculate n and totient(n)
    n = p * q
    totient = (p - 1) * (q - 1)
    
    # Choose e (public exponent)
    e = 65537  # Common value for e
    
    # Calculate d (private exponent)
    d = mod_inverse(e, totient)
    
    # Additional CRT parameters for private key
    p_inv = mod_inverse(p, q)
    
    # Create public and private keys
    public_key = {
        "n": n,
        "e": e
    }
    
    private_key = {
        "n": n,
        "d": d,
        "p": p,
        "q": q,
        "p_inv": p_inv
    }
    
    return public_key, private_key

def int_to_hex(n: int) -> str:
    """
    Convert integer to hexadecimal string
    
    Args:
        n: Integer to convert
        
    Returns:
        str: Hexadecimal string
    """
    return hex(n)[2:]  # Remove '0x' prefix

def hex_to_int(hex_str: str) -> int:
    """
    Convert hexadecimal string to integer
    
    Args:
        hex_str: Hexadecimal string
        
    Returns:
        int: Integer value
    """
    return int(hex_str, 16)

def save_key_to_file(key: Dict[str, int], filename: str, key_type: str) -> None:
    """
    Save key to file in hexadecimal format
    
    Args:
        key: The key (public or private) as a dictionary
        filename: The filename to save to
        key_type: The type of key ("PUBLIC" or "PRIVATE")
    """
    content = [f"{k}:{int_to_hex(v)}" for k, v in key.items()]
    key_str = "\n".join(content)
    
    with open(filename, "w") as f:
        f.write(f"-----BEGIN {key_type} KEY-----\n")
        f.write(key_str)
        f.write(f"\n-----END {key_type} KEY-----\n")

def load_key_from_file(filename: str) -> Dict[str, int]:
    """
    Load key from file
    
    Args:
        filename: The filename to load from
        
    Returns:
        Dict[str, int]: The key as a dictionary
    """
    with open(filename, "r") as f:
        content = f.read()
    
    # Extract key data between BEGIN and END markers
    start_marker = "-----BEGIN"
    end_marker = "-----END"
    
    start_idx = content.find("\n", content.find(start_marker)) + 1
    end_idx = content.find(end_marker)
    
    key_data = content[start_idx:end_idx].strip()
    key_pairs = key_data.split("\n")
    
    key = {}
    for pair in key_pairs:
        k, v = pair.split(":")
        key[k] = hex_to_int(v)
    
    return key

def generate_and_save_keypair(
        bits: int = 2048,
        public_key_file: str = "public_key.txt",
        private_key_file: str = "private_key.txt"
    ) -> None:
    """
    Generate RSA key pair and save to files
    
    Args:
        bits: The bit length for the RSA modulus
        public_key_file: Filename for public key
        private_key_file: Filename for private key
    """
    public_key, private_key = generate_rsa_keypair(bits)
    save_key_to_file(public_key, public_key_file, "PUBLIC")
    save_key_to_file(private_key, private_key_file, "PRIVATE")
    print(f"Key pair generated and saved to {public_key_file} and {private_key_file}")

if __name__ == "__main__":
    # Example usage
    generate_and_save_keypair()
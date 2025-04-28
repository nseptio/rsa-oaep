# RSA-OAEP:

## Preparation
1. Setup Venv
```
python -m venv venv

venv/Scripts/activate.bat
```
2. Install dependecy
```
pip install -r requirements.txt
```
3. Run GUI
```
python gui.py
```

## Format Key:
### Public Key:
**\keys\public_key.txt**
```
-----BEGIN PUBLIC KEY-----
n:<VALUE>
e:<VALUE>
-----END PUBLIC KEY-----
```

### Private Key:
**\keys\private_key.txt**
```
-----BEGIN PRIVATE KEY-----
n:<VALUE>
d:<VALUE>
-----END PRIVATE KEY-----
```


## OAEP Implementation
![oaep-visualization](oaep.png)

Source:https://www.johndcook.com/blog/2023/08/05/rsa-oaep/

Implementation in: 
**encrypt.py**

Function:
```
def oaep_pad(message: bytes, k: int, label: bytes = b"") -> bytes:
```

Operation:
```
# Compute label hash
lHash = sha256(label)
    
# Generate padding string
PS = b'\x00' * (k - mLen - 2 * hLen - 2)
    
# Construct data block
DB = lHash + PS + b'\x01' + message
    
# Generate random seed
seed = os.urandom(hLen)
    
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
```

## RSA-OAEP Implementation

### Encryption Process
Implementation in
`encrypt.py`, `encrypt_block()`:
```
# Apply OAEP padding
padded_message = oaep_pad(message, k)
# Apply RSA encryption
encrypted = rsa_encrypt(padded_message, n, e)

```

**NOTES: Details are omitted, the full implementation is at encrypt.py file**

### Decryption Process
Implementation in
`decrypt.py`, `decrypt_block()`:
```
# Decryption
decrypted_padded = rsa_decrypt(ciphertext, n, d)
        
# Remove OAEP padding
return oaep_unpad(decrypted_padded, k)
```
**NOTES: Details are omitted, the full implementation is at decrypt.py file**

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
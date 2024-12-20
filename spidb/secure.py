import string, random, os, base64
from collections import namedtuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.backends import default_backend
import bcrypt
from typing import Union

### ------- User Enabled Functions ------- ####
# random UUID with params
def generate_uuid(letts: bool = True, digs: bool = True, puncs: bool = False, length: int = 32) -> str:
    characters = ''
    
    if letts:
        characters += string.ascii_letters
    if digs:
        characters += string.digits
    if puncs:
        characters += string.punctuation

    return ''.join(random.choices(characters, k=length))

# decode bytes
def decode_bytes(*values):    
    if len(values) == 1:
        value = values[0]
        return base64.b64encode(value).decode('utf-8') if isinstance(value, bytes) else value
    else:
        return tuple(base64.b64encode(v).decode('utf-8') if isinstance(v, bytes) else v for v in values)

# hash comparison
def verify_password(plain_password: str or bytes, hashed_password: str or bytes) -> bool: # type: ignore
    plain_password, hashed_password = __convert_bytes(plain_password, hashed_password)
        
    return bcrypt.checkpw(plain_password, hashed_password)

# rsa key pair            
def generate_rsa_key_pair(pub_exp: int = 65537, key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=pub_exp,key_size=key_size,backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# serialize private to save
def serialize_private_key(private_key, password: Union[str, bytes] = None):
    if password:
        password = __convert_bytes(password)
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=encryption_algorithm)
    
    return private_pem

# serialize public to save
def serialize_public_key(public_key):
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_pem

# deserialize public to crypt
def deserialize_public_key(public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    return public_key

# deserialize private to crypt
def deserialize_private_key(private_key_pem, password: Union[str,bytes] = None):
    if password:
        password = __convert_bytes(password)
        
    private_key = serialization.load_pem_private_key(private_key_pem, password=password, backend=default_backend())
    return private_key

# encrypt data using the public key
def encrypt_password(public_key, data):
    if isinstance(public_key, bytes):
        try:
            if b"-----BEGIN PUBLIC KEY-----" in public_key:
                public_key = deserialize_public_key(public_key)
        except ValueError as e:
            print(f"Failed to deserialize public key:{e}")
    
    data = __convert_bytes(data)
    enc_data = __encrypt_data(data)
    encrypted_data = public_key.encrypt(enc_data.ct, pad.OAEP(algorithm=hashes.SHA256(), mgf=pad.MGF1(algorithm=hashes.SHA256()), label=None))
    return base64.b64encode(encrypted_data), enc_data

# Decrypt data using the private key
def decrypt_password(private_key, encrypted_data, key, iv, private_pass: Union[str,bytes] = None):
    if isinstance(private_key, bytes):
        try:
            if b"-----BEGIN RSA PRIVATE KEY-----" in private_key:
                private_key = deserialize_private_key(private_key, password=private_pass)
        except ValueError as e:
            print(f"Failed to deserialize public key:{e}")
            
    encrypted_data = __convert_base64(encrypted_data)
    decrypted_data = private_key.decrypt(encrypted_data, pad.OAEP(algorithm=hashes.SHA256(), mgf=pad.MGF1(algorithm=hashes.SHA256()), label=None))
    decrypted_data = __decrypt_data(decrypted_data, key, iv)
    return decrypted_data

### ------- User Not Enabled Functions ------- ####

# named tuple
@property
def __create_namedtuple(name, **fields):
    return namedtuple(name, fields.keys())(**fields)

# convert to bytes
@property
def __convert_bytes(*values):
    if len(values) == 1:
        value = values[0]
        return value.encode('ascii') if isinstance(value, str) else value
    else:
        return tuple(v.encode('ascii') if isinstance(v, str) else v for v in values)

# convert to base64
@property
def __convert_base64(*values):
    if len(values) == 1:
        value = values[0]
        return base64.b64decode(value) if isinstance(value, str) else value
    else:
        return [base64.b64decode(v) if isinstance(v, str) else v for v in values]

# encrypting any password with AES
@property
def __encrypt_hash(password: str or bytes) -> str: # type: ignore
    password = __convert_bytes(password)
    
    key = os.urandom(32)        
    iv = os.urandom(16)
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return __create_namedtuple('ENCHASH', ct=ct, key=key, iv=iv)

# create hash + salt + AES
@property
def __encrypt_data(plain_password: str or bytes, salt_rounds: int = 12, salt_prefix: Union[str, bytes] = b'2b') -> str: # type: ignore   
    # print("Input plaintext password: " + plain_password)
    # print("Input salt rounds: " + str(salt_rounds))
    # print("Input salt prefix: " + salt_prefix.decode("utf-8"))
    
    plain_password, salt_rounds, salt_prefix = __convert_bytes(plain_password, salt_rounds, salt_prefix)
    
    salt = bcrypt.gensalt(salt_rounds,salt_prefix)    
    hashed_password = bcrypt.hashpw(plain_password, salt)
    ct, key, iv = __encrypt_hash(hashed_password)
    
    return __create_namedtuple('ENCPASS', ct=ct, key=key, iv=iv)

# decrypt AES + hash + salt password
@property
def __decrypt_data(password: str or bytes, key: str or bytes, iv: str or bytes) -> bool: # type: ignore
    password, key, iv = __convert_base64(password, key, iv) 
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(password) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data
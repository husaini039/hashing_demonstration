import hashlib
import os

def generate_secure_sha256_hash(input_string, salt=None, rounds=100000):

    if salt is None:
        # Generate a cryptographically strong random salt (16 bytes = 32 hex chars)
        salt = os.urandom(16)
    
    # Combine the salt with the input string before hashing
    # input_string must be encoded to bytes (e.g., UTF-8)
    salted_input = salt + input_string.encode('utf-8')

    # Perform multiple rounds of hashing (key stretching)
    current_hash = salted_input
    for _ in range(rounds):
        # Hash the previous hash's binary output
        current_hash = hashlib.sha256(current_hash).digest() 

    # Convert the final hash and the salt to hexadecimal strings for storage/display
    hex_hash = current_hash.hex()
    hex_salt = salt.hex()

    return hex_hash, hex_salt



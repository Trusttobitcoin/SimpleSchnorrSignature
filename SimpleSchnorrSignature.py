import os
import hashlib
import ecdsa

# Function to generate a private and public key pair
def generate_keys():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

# Function to create a Schnorr signature (simplified version)
def schnorr_sign(message, private_key):
    # Hash the message
    message_hash = hashlib.sha256(message).digest()

    # Generate a random nonce
    nonce = os.urandom(32)
    nonce_int = int.from_bytes(nonce, byteorder="big") % private_key.curve.order

    # Calculate R
    R = private_key.curve.generator * nonce_int
    R_x = R.x()

    # Calculate hash of R_x, public key, and message hash
    h = hashlib.sha256()
    h.update(R_x.to_bytes(32, byteorder="big"))
    h.update(private_key.get_verifying_key().to_string())
    h.update(message_hash)
    h_int = int.from_bytes(h.digest(), byteorder="big") % private_key.curve.order

    # Calculate s
    s = (nonce_int + h_int * int.from_bytes(private_key.to_string(), byteorder="big")) % private_key.curve.order

    return (R_x, s)

# Function to verify a Schnorr signature (simplified version)
def schnorr_verify(message, signature, public_key):
    R_x, s = signature

    # Calculate hash of R_x, public key, and message hash
    message_hash = hashlib.sha256(message).digest()
    h = hashlib.sha256()
    h.update(R_x.to_bytes(32, byteorder="big"))
    h.update(public_key.to_string())
    h.update(message_hash)
    h_int = int.from_bytes(h.digest(), byteorder="big") % public_key.curve.order

    # Correctly handle point subtraction on the elliptic curve
    R = (public_key.curve.generator * s) + (public_key.pubkey.point * -h_int)

    return R.x() == R_x

# Example usage
private_key, public_key = generate_keys()
message = b"Hello, Schnorr!"
signature = schnorr_sign(message, private_key)
print("Signature valid:", schnorr_verify(message, signature, public_key))

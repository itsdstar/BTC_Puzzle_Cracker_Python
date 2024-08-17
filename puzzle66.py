import ecdsa
import hashlib
import base58
import random
import time
from Crypto.Hash import RIPEMD160  # Import RIPEMD160 from pycryptodome


def private_key_to_compressed_address(private_key_int):
    # Convert the private key integer to a 32-byte string
    private_key_bytes = private_key_int.to_bytes(32, byteorder='big')

    # Generate public key from private key using ECDSA and secp256k1
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Compress the public key (33 bytes, starts with 0x02 or 0x03 depending on y-coord parity)
    public_key_bytes = b'\x02' + vk.to_string(
    )[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]

    # SHA-256 hashing
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()

    # RIPEMD-160 hashing using pycryptodome
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()

    # Add network byte (0x00 for mainnet)
    network_byte = b'\x00' + ripemd160_bpk

    # Double SHA-256 hashing for checksum
    checksum = hashlib.sha256(
        hashlib.sha256(network_byte).digest()).digest()[:4]

    # Add checksum and encode as Base58
    address_bytes = network_byte + checksum
    address = base58.b58encode(address_bytes)

    return address.decode()


# Define the range and the known address
start_range = 0x2000000000000000
end_range = 0x3FFFFFFFFFFFFFFF
known_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"

# Number of keys to test
total_keys_to_test = 99999999999999999999999999999999999999999999999999999999
progress_interval = 100000

# Initialize counters
keys_tested = 0

start_time = time.time()

for _ in range(total_keys_to_test):
    # Generate a random private key within the specified range
    private_key = random.randint(start_range, end_range)

    # Generate the corresponding Bitcoin address
    generated_address = private_key_to_compressed_address(private_key)

    # Check if the generated address matches the known address
    if generated_address == known_address:
        print(f"\nPrivate key found: {hex(private_key)}")
        break

    keys_tested += 1

    # Display progress
    if keys_tested % progress_interval == 0:
        elapsed_time = time.time() - start_time
        print(
            f"\rKeys tested: {keys_tested}/{total_keys_to_test}, Time elapsed: {elapsed_time:.2f} seconds",
            end='')

else:
    print(f"\nPrivate key not found after testing {total_keys_to_test} keys.")

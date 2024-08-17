import ecdsa  # For elliptic curve cryptography, specifically the secp256k1 curve used in Bitcoin
import hashlib  # For hashing (SHA-256 and RIPEMD-160) used in Bitcoin address generation
import base58  # For Base58 encoding, which is used in Bitcoin addresses
import random  # For generating random private keys within a specific range
import time  # For measuring the time taken and progress tracking
from concurrent.futures import ThreadPoolExecutor, as_completed  # For parallel processing

def private_key_to_compressed_address(private_key_int):
    """
    Converts a private key to a Bitcoin compressed address.
    """
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

    # RIPEMD-160 hashing
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()

    # Add network byte (0x00 for mainnet)
    network_byte = b'\x00' + ripemd160_bpk

    # Double SHA-256 hashing for checksum
    checksum = hashlib.sha256(
        hashlib.sha256(network_byte).digest()).digest()[:4]

    # Add checksum and encode as Base58
    address_bytes = network_byte + checksum
    address = base58.b58encode(address_bytes)

    return address.decode()


def test_private_key(known_address, start_range, end_range):
    """
    Generates a random private key within the specified range, converts it to a compressed Bitcoin address,
    and checks if it matches the known address.
    """
    # Generate a random private key within the specified range
    private_key = random.randint(start_range, end_range)

    # Generate the corresponding Bitcoin address
    generated_address = private_key_to_compressed_address(private_key)

    # Return the private key if the generated address matches the known address
    if generated_address == known_address:
        return private_key

    return None


def main():
    # Define the range and the known address
    start_range = 0x2000000000000000
    end_range = 0x3FFFFFFFFFFFFFFF
    known_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Replace with the actual known compressed Bitcoin address

    # Number of keys to test
    total_keys_to_test = 10000000  # Adjust this to your desired number of tests
    batch_size = 1000  # Set the batch size for parallel processing
    progress_interval = 100000  # Show progress every 100,000 keys

    # Initialize counters
    keys_tested = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=4) as executor:  # Adjust max_workers based on your CPU
        try:
            for i in range(0, total_keys_to_test, batch_size):
                # Submit tasks to the executor for key generation and address checking
                futures = [executor.submit(test_private_key, known_address, start_range, end_range) for _ in range(batch_size)]
                
                for future in as_completed(futures):
                    result = future.result()

                    if result is not None:
                        print(f"Private key found: {hex(result)}")
                        return  # Stop further processing when the key is found

                    keys_tested += 1

                    # Display progress
                    if keys_tested % progress_interval == 0:
                        elapsed_time = time.time() - start_time
                        print(f"Keys tested: {keys_tested}/{total_keys_to_test}, Time elapsed: {elapsed_time:.2f} seconds")

        except KeyboardInterrupt:
            print("Execution interrupted. Cleaning up...")

    print(f"Private key not found after testing {keys_tested} keys.")

if __name__ == "__main__":
    main()

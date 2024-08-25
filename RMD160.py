import ecdsa
import hashlib
import base58
from Crypto.Hash import RIPEMD160
import time
import os
import threading


# Function to log output to both console and file
def log_output(message, log_file):
    print(message)
    with open(log_file, "a") as f:
        f.write(message + "\n")


# Function to clear the log file every 10 minutes
def clear_log_file_periodically(log_file, interval=600):
    while True:
        time.sleep(interval)
        with open(log_file, "w") as f:
            f.write("")  # Clear the file
        print(f"\nLog file cleared at {time.strftime('%Y-%m-%d %H:%M:%S')}")


def private_key_to_compressed_address(private_key_int):
    private_key_bytes = private_key_int.to_bytes(32, byteorder="big")
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key_bytes = (b"\x02" + vk.to_string()[:32] if vk.pubkey.point.y() %
                        2 == 0 else b"\x03" + vk.to_string()[:32])
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()
    network_byte = b"\x00" + ripemd160_bpk
    checksum = hashlib.sha256(
        hashlib.sha256(network_byte).digest()).digest()[:4]
    address_bytes = network_byte + checksum
    return base58.b58encode(address_bytes).decode()


def check_partial_match(known_address, generated_address):
    return known_address[:2] == generated_address[:2]


def find_private_key(start_range, end_range, known_address, log_file):
    keys_tested = 0
    progress_interval = 10000
    batch_size = 1000
    start_time = time.time()

    private_key = end_range
    total_keys = end_range - start_range + 1

    while private_key >= start_range:
        batch_start = max(private_key - batch_size, start_range - 1)

        for key in range(private_key, batch_start, -1):
            generated_address = private_key_to_compressed_address(key)

            if check_partial_match(known_address, generated_address):
                log_output(
                    f"\nPartial match found! Private key: {hex(key)}, Address: {generated_address}",
                    log_file,
                )

            if generated_address == known_address:
                log_output(f"\nPrivate key found: {hex(key)}", log_file)
                return key

        keys_tested += private_key - batch_start
        private_key = batch_start

        if keys_tested % progress_interval == 0:
            elapsed_time = time.time() - start_time
            keys_remaining = total_keys - keys_tested
            time_per_key = elapsed_time / keys_tested
            est_time_remaining = time_per_key * keys_remaining
            log_output(
                f"\rKeys tested: {keys_tested}/{total_keys}, "
                f"Time elapsed: {elapsed_time:.2f}s, "
                f"Est. time remaining: {est_time_remaining:.2f}s",
                log_file,
            )

    log_output("\nPrivate key not found within the given range.", log_file)
    return None


if __name__ == "__main__":
    start_range = 0x20000000000000000
    end_range = 0x3fffffffff013e281
                #0x3ffffffffffffffff
    known_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    log_file = "output_log.txt"

    # Clear the log file at the start of the program
    with open(log_file, "w") as f:
        f.write("")

    # Start a background thread to clear the log file periodically
    log_clear_thread = threading.Thread(target=clear_log_file_periodically,
                                        args=(log_file, ))
    log_clear_thread.daemon = True  # Ensure thread exits when the main program exits
    log_clear_thread.start()

    # Start the key search
    find_private_key(start_range, end_range, known_address, log_file)

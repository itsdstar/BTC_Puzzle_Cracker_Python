import ecdsa
import hashlib
import base58
from Crypto.Hash import RIPEMD160
import time
import os
import concurrent.futures
import threading
import numpy as np
import pickle
from bloom_filter import BloomFilter

# Increased Bloom filter size
bloom_size = 100000000  # 100 million elements
bloom_filter = BloomFilter(max_elements=bloom_size, error_rate=0.01)

def log_output(message, log_file):
    print(message)
    with open(log_file, "a") as f:
        f.write(message + "\n")

def clear_log_file_periodically(log_file, interval=600):
    while True:
        time.sleep(interval)
        with open(log_file, "w") as f:
            f.write("")
        print(f"\nLog file cleared at {time.strftime('%Y-%m-%d %H:%M:%S')}")

def generate_advanced_heatmap(start_range, end_range, segments=1000):
    heatmap = {}
    segment_size = (end_range - start_range) // segments
    for i in range(segments):
        bias = np.random.normal(loc=0.5, scale=0.1)
        heatmap[(start_range + i * segment_size, start_range + (i + 1) * segment_size - 1)] = max(0, min(1, bias))
    return heatmap

def update_heatmap(heatmap, key_segment, weight=0.1):
    if key_segment in heatmap:
        heatmap[key_segment] += weight
    # Normalize the heatmap
    total = sum(heatmap.values())
    for key in heatmap:
        heatmap[key] /= total

def reprioritize_search_space(heatmap):
    return sorted(heatmap.keys(), key=lambda k: heatmap[k], reverse=True)

def save_heatmap(heatmap, filename="heatmap.pkl"):
    try:
        with open(filename, "wb") as f:
            pickle.dump(heatmap, f)
        print(f"Heatmap saved successfully to {filename}")
    except Exception as e:
        print(f"Failed to save heatmap: {e}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Heatmap size: {len(heatmap)}")

def load_heatmap(filename="heatmap.pkl"):
    if os.path.exists(filename):
        try:
            with open(filename, "rb") as f:
                print(f"Loading heatmap from {filename}")
                return pickle.load(f)
        except Exception as e:
            print(f"Failed to load heatmap: {e}")
    else:
        print(f"No heatmap file found, starting fresh.")
    return {}

def private_key_to_compressed_address(private_key_int):
    if private_key_int in bloom_filter:
        return None
    private_key_bytes = private_key_int.to_bytes(32, byteorder="big")
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key_bytes = (b"\x02" + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b"\x03" + vk.to_string()[:32])
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()
    network_byte = b"\x00" + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address_bytes = network_byte + checksum
    bloom_filter.add(private_key_int)
    return base58.b58encode(address_bytes).decode()

def check_partial_match(known_address, generated_address):
    # Increased partial match length to 4 characters
    return known_address[:4] == generated_address[:4]

def worker(node_id, key_range, known_address, log_file, heatmap):
    start_key, end_key = key_range
    progress_interval = 10000
    keys_tested = 0
    start_time = time.time()

    for private_key in range(end_key, start_key, -1):
        generated_address = private_key_to_compressed_address(private_key)
        if generated_address is None:
            continue

        if check_partial_match(known_address, generated_address):
            log_output(f"\nPartial match found by Node {node_id}! Private key: {hex(private_key)}, Address: {generated_address}", log_file)
            update_heatmap(heatmap, key_range, weight=0.05)

        if generated_address == known_address:
            log_output(f"\nPrivate key found by Node {node_id}: {hex(private_key)}", log_file)
            return private_key

        keys_tested += 1
        if keys_tested % progress_interval == 0:
            elapsed_time = time.time() - start_time
            log_output(f"\rNode {node_id}: Keys tested: {keys_tested}, Time elapsed: {elapsed_time:.2f}s", log_file)

    return None

def find_private_key_optimized(start_range, end_range, known_address, log_file, num_nodes=4):
    heatmap = load_heatmap()

    if not heatmap:
        print("Generating new heatmap...")
        heatmap = generate_advanced_heatmap(start_range, end_range)
        print("New heatmap generated. Attempting to save...")
        save_heatmap(heatmap)

    iteration = 0
    while True:  # Continuous search until the key is found
        iteration += 1
        print(f"Starting iteration {iteration}")
        key_blocks = reprioritize_search_space(heatmap)
        key_segments = [(start, end) for (start, end) in key_blocks]

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_nodes) as executor:
            futures = []
            for i in range(num_nodes):
                if i < len(key_segments):
                    key_range = key_segments[i]
                    futures.append(executor.submit(worker, i, key_range, known_address, log_file, heatmap))

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    print("Key found. Saving final heatmap...")
                    save_heatmap(heatmap)
                    return result

        print(f"Iteration {iteration} completed. Saving heatmap...")
        save_heatmap(heatmap)
        log_output(f"Search iteration {iteration} completed. Reprioritizing search space.", log_file)

if __name__ == "__main__":
    start_range = 0x20000000000000000
    end_range = 0x3fffffffff013e281
    known_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    log_file = "output_log.txt"

    with open(log_file, "w") as f:
        f.write("")

    log_clear_thread = threading.Thread(target=clear_log_file_periodically, args=(log_file,))
    log_clear_thread.daemon = True
    log_clear_thread.start()

    print("Starting private key search...")
    result = find_private_key_optimized(start_range, end_range, known_address, log_file)
    if result:
        print(f"Private key found: {hex(result)}")
    else:
        print("Search completed without finding the private key.")
import hashlib
import timeit
import os
import matplotlib.pyplot as plt
from urllib.request import urlopen


def hash_with_algorithm(data, algorithm):
    """
    Hashes input data using the specified algorithm.

    Args:
    - data: Input data to be hashed.
    - algorithm: Hashing algorithm to be used.

    Returns:
    - Hashed output.
    - Time taken for hashing.
    """
    start_time = timeit.default_timer()
    hasher = hashlib.new(algorithm)
    hasher.update(data)

    try:
        hashed_output = hasher.digest()
    except TypeError:  # In case digest() raises an error
        length = None
        if algorithm in {'sha512_224', 'sha224'}:
            length = 28
        elif algorithm in {'blake2s'}:
            length = 32
        elif algorithm in {'sha256', 'sha3_256', 'md5', 'md4', 'ripemd160', 'sm3', 'mdc2'}:
            length = 64
        elif algorithm in {'sha384', 'sha3_384'}:
            length = 96
        elif algorithm in {'blake2b', 'sha512', 'sha3_512', 'md5-sha1', 'sha512_256', 'whirlpool'}:
            length = 128
        elif algorithm in {'shake_128', 'sha3_224'}:
            length = 56
        elif algorithm in {'shake_256'}:
            length = 64

        if length is None:
            raise ValueError(f"Unknown length for algorithm: {algorithm}")

        hashed_output = hasher.digest(length)

    elapsed_time = timeit.default_timer() - start_time
    return hashed_output, elapsed_time


def download_file(url, filename):
    """
    Downloads a file from the given URL and saves it with the specified filename.

    Args:
    - url: URL of the file to download.
    - filename: Name of the file to save.

    Returns:
    - True if the file was downloaded successfully, False otherwise.
    """
    try:
        with urlopen(url) as response, open(filename, 'wb') as out_file:
            out_file.write(response.read())
        return True
    except Exception as e:
        print(f"Error downloading file: {e}")
        return False

def hash_file(filepath, algorithm='sha256'):
    """
    Hashes a binary file from disk using the specified algorithm.

    Args:
    - filepath: Path to the file to be hashed.
    - algorithm: Hashing algorithm to be used.

    Returns:
    - Hashed output.
    """
    try:
        with open(filepath, 'rb') as file:
            data = file.read()
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error hashing file: {e}")
        return None


def generate_hash_speed_test(message_sizes, algorithm='sha256'):
    """
    Tests the speed of generating hashes for messages of different sizes.

    Args:
    - message_sizes: List of message sizes to test.
    - algorithm: Hashing algorithm to be used.

    Returns:
    - List of tuples containing message size and corresponding hashing time.
    """
    results = []
    for size in message_sizes:
        message = b'a' * size
        _, elapsed_time = hash_with_algorithm(message, algorithm)
        results.append((size, elapsed_time))
    return results

def plot_hash_speed(results):
    """
    Plots the hashing speed results.

    Args:
    - results: List of tuples containing message size and corresponding hashing time.
    """
    sizes, times = zip(*results)
    plt.plot(sizes, times)
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('Time (seconds)')
    plt.title('Hashing Speed vs Message Size')
    plt.show()

if __name__ == "__main__":
    # Task 1: Hashing input data
    print("Task 1")
    data = input("Enter data to hash: ").encode('utf-8')
    algorithms = ['sha3_512', 'blake2s', 'md5', 'sha384', 'shake_256', 'sha3_384', 'blake2b', 'sha1', 'sm3', 'ripemd160', 'sha3_224', 'shake_128', 'mdc2', 'sha512', 'whirlpool', 'md4', 'md5-sha1', 'sha512_256', 'sha512_224', 'sha224', 'sha3_256', 'sha256']
    for algorithm in algorithms:
        hashed_output, elapsed_time = hash_with_algorithm(data, algorithm)
        print(f"{algorithm}: {hashed_output} (Time: {elapsed_time} seconds)")

    # Task 2: Open and hash the file
    print("\nTask 2")
    filepath = 'C:/Users/lepsz/Downloads/ubuntu-20.04.3-desktop-amd64.iso'  # Enter the path to your ISO file
    computed_hash = hash_file(filepath, 'md5')
    if computed_hash:
        expected_hash = '7b9e8a8e1986f4b0b28f0c5ab84b2728'
        if computed_hash == expected_hash:
            print("Hash verification successful.")
        else:
            print("Hash verification failed.")
    else:
        print("Failed to hash the file.")

    # Task 3: Hashing a binary file from disk
    print("\nTask 3")
    filepath = 'C:/Users/lepsz/Downloads/ubuntu-20.04.3-desktop-amd64.iso'  # Enter the path to your ISO file
    computed_hash = hash_file(filepath, 'md5')
    if computed_hash:
        print(f"MD5 hash of the file: {computed_hash}")
    else:
        print("Failed to hash the file.")

    # Task 4: Speed test and plotting
    print("Task 4")
    message_sizes = [1000, 10000, 100000, 1000000, 10000000]  # Example message sizes
    results = generate_hash_speed_test(message_sizes)
    plot_hash_speed(results)
    print("END")
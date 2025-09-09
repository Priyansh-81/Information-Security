import hashlib
import random
import string
import time


# Generate random dataset
def generate_random_strings(n, length=10):
    dataset = []
    for _ in range(n):
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(s)
    return dataset


# Hashing function using hashlib
def compute_hash(data, algo):
    if algo == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()


# Experiment: hash dataset, measure time, detect collisions
def experiment(dataset, algo):
    hashes = {}
    collisions = []

    start_time = time.time()

    for s in dataset:
        h = compute_hash(s, algo)
        if h in hashes:
            collisions.append((s, hashes[h]))
        else:
            hashes[h] = s

    end_time = time.time()
    elapsed = end_time - start_time

    return elapsed, collisions


def main():
    # Generate dataset of 50–100 random strings
    n = random.randint(50, 100)
    dataset = generate_random_strings(n)

    print(f"Dataset size: {n}\n")

    for algo in ["md5", "sha1", "sha256"]:
        elapsed, collisions = experiment(dataset, algo)
        print(f"Algorithm: {algo.upper()}")
        print(f"Time taken: {elapsed:.6f} seconds")
        print(f"Collisions found: {len(collisions)}\n")


if __name__ == "__main__":
    main()
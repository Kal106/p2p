import hashlib


def getHashKey(data) :
    return hashlib.sha256(data.encode()).hexdigest()

def split_file_into_chunks(file_path, chunk_size, grpId):
    chunks_meta_hash = {}
    chunk_hashes = []

    try:
        with open(file_path, 'rb') as f:
            offset = 0
            index = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                sha = hashlib.sha256(chunk).hexdigest()

                # Unique key: SHA256 of (file_path + chunk hash), encoded as bytes
                key_input = grpId + sha
                key = hashlib.sha1(key_input.encode()).hexdigest()
                chunk_hashes.append(sha)

                chunks_meta_hash[key] = {
                    "index": index,
                    "start": offset,
                    "end": offset + len(chunk) - 1,
                    "sha256": sha
                }

                offset += len(chunk)
                index += 1

    except Exception as e:
        print(f"Error reading file: {e}")
        return {}, []

    return chunks_meta_hash, chunk_hashes



def compute_merkle_root(hashes):
    """Builds a Merkle tree and returns the root hash."""
    if not hashes:
        return None
    current = hashes
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                combined = current[i] + current[i + 1]
            else:
                combined = current[i] + current[i]
            combined_hash = hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(combined_hash)
        current = next_level
    return current[0]

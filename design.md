# Bessie

## Encrypt

- generate a random 24-byte nonce
- for each chunk:
    - (chunk_auth_key, chunk_stream_key) = keyed_hash(LTK, nonce + chunk_index + final_flag)[:64]
        - final_flag is one byte, 0 for non-final chunks and 1 for the final (short) chunk
    - auth_tag = keyed_hash(chunk_auth_key, chunk)[:32]
        - 32 bytes rather than 16 here provides key commitment
    - chunk_stream = keyed_hash(chunk_stream_key, auth_tag)[:chunk_len]
        - incorporating the tag into the stream provides *some* misuse resistance, but chunk swapping and the CPSS attack remain
    - chunk_ciphertext = xor(chunk, chunk_stream) + auth_tag
- ciphertext is the random nonce followed by each chunk_ciphertext

## Decrypt

- for each chunk:
    - (chunk_auth_key, chunk_stream_key) = keyed_hash(LTK, nonce + chunk_index + final_flag)[:64]
    - chunk_stream = keyed_hash(chunk_stream_key, auth_tag)[:chunk_len]
    - chunk = xor(chunk_ciphertext, chunk_stream)
    - expected_tag = keyed_hash(chunk_auth_key, chunk)[:32]
    - constant-time comparison between auth_tag and expected_tag


## Seek

- if length not yet verified:
    - seek to end to get the apparent length
    - verify the final chunk to verify the length
- seek to target chunk
- decrypt and buffer target chunk

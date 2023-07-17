from blake3 import blake3
import secrets

KEY_LEN: int = blake3.key_size
NONCE_LEN: int = 24
TAG_LEN: int = blake3.digest_size
# Note that the Bessie chunk length (16 KiB) is different from the BLAKE3 chunk
# length (1 KiB).
CHUNK_LEN: int = 16384
CIPHERTEXT_CHUNK_LEN: int = CHUNK_LEN + TAG_LEN


def chunk_keys(
    key: bytes, nonce: bytes, chunk_index: int, is_final: bool
) -> tuple[bytes, bytes]:
    input = nonce + chunk_index.to_bytes(8, "little") + bytes([is_final])
    output = blake3(input, key=key).digest(2 * KEY_LEN)
    auth_key = output[:KEY_LEN]
    stream_key = output[KEY_LEN:]
    return (auth_key, stream_key)


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = bytearray(nonce)
    chunk_start = 0
    while True:
        plaintext_chunk = plaintext[chunk_start : chunk_start + CHUNK_LEN]
        chunk_index = chunk_start // CHUNK_LEN
        is_final = len(plaintext_chunk) < CHUNK_LEN
        auth_key, stream_key = chunk_keys(key, nonce, chunk_index, is_final)
        tag = blake3(plaintext_chunk, key=auth_key).digest()
        stream = blake3(tag, key=stream_key).digest(len(plaintext_chunk))
        ciphertext.extend(xor(plaintext_chunk, stream))
        ciphertext.extend(tag)
        if is_final:
            return ciphertext
        chunk_start += CHUNK_LEN


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    assert len(ciphertext) >= NONCE_LEN
    nonce = ciphertext[:NONCE_LEN]
    plaintext = bytearray()
    chunk_start = NONCE_LEN
    while True:
        ciphertext_chunk = ciphertext[chunk_start : chunk_start + CIPHERTEXT_CHUNK_LEN]
        assert len(ciphertext_chunk) >= TAG_LEN
        chunk_index = chunk_start // CIPHERTEXT_CHUNK_LEN
        is_final = len(ciphertext_chunk) < CIPHERTEXT_CHUNK_LEN
        auth_key, stream_key = chunk_keys(key, nonce, chunk_index, is_final)
        tag = ciphertext_chunk[-TAG_LEN:]
        stream = blake3(tag, key=stream_key).digest(len(ciphertext_chunk) - TAG_LEN)
        plaintext_chunk = xor(ciphertext_chunk[:-TAG_LEN], stream)
        expected_tag = blake3(plaintext_chunk, key=auth_key).digest()
        if not secrets.compare_digest(tag, expected_tag):
            raise ValueError("invalid ciphertext")
        plaintext.extend(plaintext_chunk)
        if is_final:
            return plaintext
        chunk_start += CIPHERTEXT_CHUNK_LEN

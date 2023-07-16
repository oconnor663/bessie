from bessie import encrypt, decrypt, CHUNK_LEN, KEY_LEN
import secrets

TEST_LENGTHS = [
    0,
    1,
    CHUNK_LEN - 1,
    CHUNK_LEN,
    CHUNK_LEN + 1,
    2 * CHUNK_LEN,
    2 * CHUNK_LEN + 1,
    50_000,
]


def test_round_trip() -> None:
    for length in TEST_LENGTHS:
        print("length:", length)
        input = secrets.token_bytes(length)
        key = secrets.token_bytes(KEY_LEN)
        ciphertext = encrypt(key, input)
        plaintext = decrypt(key, ciphertext)
        assert input == plaintext

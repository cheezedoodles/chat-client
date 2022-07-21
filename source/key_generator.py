import os
import secrets


KEY_LENGTH = 1000000


def generate_files(
    chat_id,
):
    """
    This is a pseudo-random bytes generator.
    Quantum random number generator api could be used instead.
    """
    bytes = secrets.token_bytes(KEY_LENGTH)
    chat_id = str(chat_id)
    file = f"chat_{chat_id}.txt"
    path = os.path.join("keys/", file)

    with open(path, "wb") as f:
        f.write(bytes)

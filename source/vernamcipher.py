import os

import requests
import json


BASE_URL = "http://127.0.0.1:8000/"


def calculate_offset(chat_id, token):
    """
    calculates offset

    for the sake of optimization this function should be called once
    at the time of chat initialization further offset values should be
    calculated like this:

    offset + len(sent_message) in encrypt() &
    offset + len(received_message) in decrypt()

    """
    messages = requests.get(
        BASE_URL + f"api/chat/{chat_id}/", headers={"Authorization": f"Token {token}"}
    ).json()

    offset = 0

    for _, message in enumerate(messages):
        message["message"] = json.loads(message["message"])
        message_len = len(message["message"])
        offset += message_len

    return offset


def generate_key(chat_id, message, offset):
    """
    This function gets the key from the chat_id_key file
    based on the current offset and the length of the current message in bytes.
    """
    if isinstance(message, list):
        message_len = len(message)
    else:
        message_len = len(message.encode("utf8"))

    file = f"chat_{chat_id}.txt"
    path = os.path.join("keys/", file)

    with open(path, "rb") as key:
        return key.read()[offset : offset + message_len]


def encrypt(message, key):
    """Vernam cipher encryption method"""
    message = message.encode("utf8")
    encrypted_message = [i ^ j for i, j in zip(message, key)]

    return encrypted_message


def decrypt(message, key):
    """Vernam cipher decryption method"""
    seq = [i ^ j for i, j in zip(message, key)]
    decrypted_message = bytearray(seq)

    return decrypted_message.decode("utf8")

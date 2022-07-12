import requests

# A module that generates chat_key files looks something like this:
# from generatefiles import generate_files
# ////////////////////////////////////////////
# import secrets

# bytes = secrets.token_bytes(10000000)

# def generate_files(id):
#     file = f'chat_{id}_key.txt'
#     with open(file, 'wb') as file:
#         file.write(bytes)
# ///////////////////////////////////////////


def calculate_offset(chat_id):
    """
    calculates offset

    for the sake of optimization this function should be called once
    at the time of chat initialization further offset values should be
    calculated like this:

    offset + len(sent_message) in encrypt() &
    offset + len(received_message) in decrypt()

    """
    messages = requests.get(
        f'http://127.0.0.1:8000/api/chat/{chat_id}/'
    ).json()
    offset = sum([
        len(
          messages[i]['message'].encode('utf8')) for i in range(len(messages))
    ])
    return offset


def generate_key(message, offset):
    """
    This function gets the key from the chat_id_key file
    based on the current offset and the length of the current message in bytes.
    """
    if isinstance(message, list):
        message_len = len(message)
    else:
        message_len = len(message.encode('utf8'))
    with open('chat_key.txt', 'rb') as key:
        return key.readline()[offset:offset+message_len]


def encrypt(message, key):
    """ Vernam cipher encryption method """
    message = message.encode('utf8')
    encrypted_message = [i ^ j for i, j in zip(message, key)]
    return encrypted_message


def decrypt(message, key):
    """ Vernam cipher decryption method """
    decrypted_message = bytearray([i ^ j for i, j in zip(message, key)])
    return decrypted_message.decode('utf8')

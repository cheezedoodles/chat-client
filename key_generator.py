import secrets
import random

bytes = secrets.token_bytes(1000000)



def generate_files():
    """ 
    This is a pseudo-random bytes generator. 
    Quantum random number generator api could be used instead.
    """
    file = 'chat_key'
    with open(file, 'wb') as file:
        file.write(bytes)

if __name__ == '__main__':
    generate_files()
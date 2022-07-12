import secrets

bytes = secrets.token_bytes(10000000)

def generate_files(id):
    """ 
    This is a pseudo-random bytes generator. 
    Quantum random number generator api could be used instead.
    """
    file = f'chat_{id}_key.txt'
    with open(file, 'wb') as file:
        file.write(bytes)

import secrets

bytes = secrets.token_bytes(1000000)  # TODO: Лучше длинну вынеси в константу


def generate_files():  # TODO: передавай сюда chat_id и сохраняй по f-строке chat_{chat_id}
    """
    This is a pseudo-random bytes generator.
    Quantum random number generator api could be used instead.
    """
    file = 'chat_key.txt'
    with open(file, 'wb') as file:  # TODO: Лучше генерь в подпапе,
        # TODO: например keys (только не через сложение строк, а os.path.join
        file.write(bytes)


if __name__ == '__main__':
    generate_files()

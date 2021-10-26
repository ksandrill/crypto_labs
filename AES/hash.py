import os

from aes128_cipher import padding, Aes128Cipher
from constraints import BLOCK_SIZE


def write_hash(key: str, input_path: str, output_path: str = None) -> None:
    with open(input_path, 'rb') as f:
        data = f.read()
        aux_data = []
        my_hash = key
        cipher = Aes128Cipher(my_hash)
        for byte in data:
            aux_data.append(byte)
            if len(aux_data) == BLOCK_SIZE:
                my_hash = cipher.encode_data(aux_data)
                cipher.key = my_hash
                del aux_data[:]
        if 0 < len(aux_data):
            padding(aux_data, BLOCK_SIZE)
            my_hash = cipher.encode_data(aux_data)
        output_path = os.path.join(os.path.dirname(input_path), 'hash_' + os.path.basename(
            input_path)) if output_path is None else output_path
        with open(output_path, 'xb') as ff:
            ff.write(bytes(my_hash))


if __name__ == '__main__':
    write_hash('dafaq', 'sample_data/dafaq.txt')

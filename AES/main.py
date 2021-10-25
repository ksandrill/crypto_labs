import os

import aes128_cipher
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', metavar='mode', help="encode for encoding and decode for decoding", type=str)
    parser.add_argument("key", metavar="key", default=None,
                        help="key for aes cipher, len(key) <=16", type=str)
    parser.add_argument("input_file", metavar="input_file",
                        help="path to input file", type=str)
    parser.add_argument("output_file", metavar="output_file", default=None,
                        help="path to output file", type=str, nargs='?')
    args = parser.parse_args()
    mode = args.mode
    key = args.key
    input_file = args.input_file
    output_file = args.output_file
    if (len(key)) > 16 or len(key) < 0:
        raise Exception('key length should be in [1,16]')
    if not os.path.isfile(input_file):
        raise Exception('input file doesnt_exist')
    cipher = aes128_cipher.Aes128Cipher(key)
    if mode == 'encode':
        cipher.encode_file(input_file, output_file)
    elif mode == 'decode':
        cipher.decode_file(input_file, output_file)
    else:
        raise Exception('wrong mode, please write encode or decode')

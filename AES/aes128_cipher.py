import os
from collections import Callable

from constraints import *
from util import *


def sub_bytes(state: list[list[int]], box: list[int]) -> None:
    for i in range(len(state)):
        for j in range(len(state[i])):
            row = state[i][j] // 0x10
            col = state[i][j] % 0x10
            box_elem = box[NB * NB * row + col]
            state[i][j] = box_elem


def shift_rows(state, shift_func: Callable[[int, int], [int]]) -> None:
    count = 1
    for i in range(1, NB):
        state[i] = shift_func(state[i], count)
        count += 1


def decode_mix_columns(state: list[list]) -> None:
    for i in range(NB):
        s0 = mul_by_0e(state[0][i]) ^ mul_by_0b(state[1][i]) ^ mul_by_0d(state[2][i]) ^ mul_by_09(state[3][i])
        s1 = mul_by_09(state[0][i]) ^ mul_by_0e(state[1][i]) ^ mul_by_0b(state[2][i]) ^ mul_by_0d(state[3][i])
        s2 = mul_by_0d(state[0][i]) ^ mul_by_09(state[1][i]) ^ mul_by_0e(state[2][i]) ^ mul_by_0b(state[3][i])
        s3 = mul_by_0b(state[0][i]) ^ mul_by_0d(state[1][i]) ^ mul_by_09(state[2][i]) ^ mul_by_0e(state[3][i])
        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3


def padding(padd_array: list[int], max_size: int) -> None:
    empty_spaces = max_size - len(padd_array)
    for i in range(empty_spaces - 1):
        padd_array.append(0)
    padd_array.append(1)


def encode_mix_columns(state: list[list[int]]) -> None:
    for i in range(NB):
        s0 = mul_by_02(state[0][i]) ^ mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i]
        s1 = state[0][i] ^ mul_by_02(state[1][i]) ^ mul_by_03(state[2][i]) ^ state[3][i]
        s2 = state[0][i] ^ state[1][i] ^ mul_by_02(state[2][i]) ^ mul_by_03(state[3][i])
        s3 = mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul_by_02(state[3][i])
        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3


def add_round_key(state: list[list[int]], key_schedule: list[list[int]], round_var: int = 0) -> None:
    for col in range(NK):
        s0 = state[0][col] ^ key_schedule[0][NB * round_var + col]
        s1 = state[1][col] ^ key_schedule[1][NB * round_var + col]
        s2 = state[2][col] ^ key_schedule[2][NB * round_var + col]
        s3 = state[3][col] ^ key_schedule[3][NB * round_var + col]
        state[0][col] = s0
        state[1][col] = s1
        state[2][col] = s2
        state[3][col] = s3


class Aes128Cipher:
    def __init__(self, key: str):
        self.key = [ord(symbol) for symbol in key]

    def encode_file(self, input_path: str, output_path: str = None) -> None:
        with open(input_path, 'rb') as f:
            data = f.read()
            encoded_data = []
            aux_data = []
            for byte in data:
                aux_data.append(byte)
                if len(aux_data) == BLOCK_SIZE:
                    encoded_data.extend(self._encode_data(aux_data))
                    del aux_data[:]
            if 0 < len(aux_data):
                padding(aux_data, BLOCK_SIZE)
                encoded_data.extend(self._encode_data(aux_data))
            output_path = os.path.join(os.path.dirname(input_path), 'encoded_' + os.path.basename(
                input_path)) if output_path is None else output_path
            with open(output_path, 'xb') as ff:
                ff.write(bytes(encoded_data))

    def decode_file(self, input_path: str, output_path: str = None) -> None:
        with open(input_path, 'rb') as f:
            data = f.read()
            decrypted_data = []
            aux_data = []
            for byte in data:
                aux_data.append(byte)
                if len(aux_data) == BLOCK_SIZE:
                    decrypted_data.extend(self._decode_data(aux_data))
                    del aux_data[:]
            if 0 < len(aux_data):
                padding(aux_data, BLOCK_SIZE)
                decrypted_data.extend(self._decode_data(aux_data))
        output_path = os.path.join(os.path.dirname(input_path), 'decoded_' + os.path.basename(
            input_path)) if output_path is None else output_path
        with open(output_path, 'xb') as ff:
            ff.write(bytes(decrypted_data))

    def _encode_data(self, input_bytes: list[int]) -> list[int]:
        state = [[] for _ in range(NB)]
        for r in range(NB):
            for c in range(NB):
                state[r].append(input_bytes[r + NB * c])
        key_schedule = self._key_expansion()
        add_round_key(state, key_schedule)
        rnd = 0
        for rnd in range(1, NR):
            sub_bytes(state, S_BOX)
            shift_rows(state, left_shift)
            encode_mix_columns(state)
            add_round_key(state, key_schedule, rnd)
        sub_bytes(state, S_BOX)
        shift_rows(state, left_shift)
        add_round_key(state, key_schedule, rnd + 1)
        output = [0 for _ in range(NB * NB)]
        for r in range(NB):
            for c in range(NB):
                output[r + NB * c] = state[r][c]
        return output

    def _decode_data(self, cipher: list[int]) -> list[int]:
        state = [[] for _ in range(NB)]
        for r in range(NB):
            for c in range(NB):
                state[r].append(cipher[r + NB * c])
        key_schedule = self._key_expansion()
        add_round_key(state, key_schedule, NR)
        rnd = NR - 1
        while rnd >= 1:
            shift_rows(state, right_shift)
            sub_bytes(state, INVERTED_S_BOX)
            add_round_key(state, key_schedule, rnd)
            decode_mix_columns(state)
            rnd -= 1
        shift_rows(state, right_shift)
        sub_bytes(state, INVERTED_S_BOX)
        add_round_key(state, key_schedule, rnd)
        output = [0 for _ in range(BLOCK_SIZE)]
        for r in range(NB):
            for c in range(NB):
                output[r + NB * c] = state[r][c]
        return output

    def _key_expansion(self) -> list[list[int]]:
        key_symbols = self.key
        if len(key_symbols) < NB * NK:
            for i in range(NB * NK - len(key_symbols)):
                key_symbols.append(0x01)
        key_schedule = [[] for _ in range(NB)]
        for r in range(NB):
            for c in range(NK):
                key_schedule[r].append(key_symbols[r + NB * c])
        for col in range(NK, NB * (NR + 1)):
            if col % NK == 0:
                tmp = [key_schedule[row][col - 1] for row in range(1, NB)]
                tmp.append(key_schedule[0][col - 1])
                for j in range(len(tmp)):
                    s_box_row = tmp[j] // 0x10
                    s_box_col = tmp[j] % 0x10
                    s_box_elem = S_BOX[BLOCK_SIZE * s_box_row + s_box_col]
                    tmp[j] = s_box_elem
                for row in range(NB):
                    s = (key_schedule[row][col - NB]) ^ (tmp[row]) ^ (R_CON[row][int(col / NK - 1)])
                    key_schedule[row].append(s)
            else:
                for row in range(NB):
                    s = key_schedule[row][col - NB] ^ key_schedule[row][col - 1]
                    key_schedule[row].append(s)
        return key_schedule

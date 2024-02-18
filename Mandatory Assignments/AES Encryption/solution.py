import os
import sys

# S-Box https://www2.rivier.edu/journal/roaj-fall-2010/j455-selent-aes.pdf
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Constants are derived from the powers of 2 in the finite field GF(2^8)
r_con = [
    [0x01, 0x00, 0x00, 0x00],   # round 1: 2^0
    [0x02, 0x00, 0x00, 0x00],   # round 2: 2^1
    [0x04, 0x00, 0x00, 0x00],   # round 3: 2^2
    [0x08, 0x00, 0x00, 0x00],   # round 4: 2^3
    [0x10, 0x00, 0x00, 0x00],   # round 5: 2^4
    [0x20, 0x00, 0x00, 0x00],   # round 6: 2^5
    [0x40, 0x00, 0x00, 0x00],   # round 7: 2^6
    [0x80, 0x00, 0x00, 0x00],   # round 8: 2^7
    [0x1b, 0x00, 0x00, 0x00],   # round 9: 2^4 + 2^3 + 2^1 + 2^0
    [0x36, 0x00, 0x00, 0x00]    # round 10: 2^5 + 2^4 + 2^1
]

# https://www.cs.miami.edu/home/burt/learning/Csc688.012/rijndael/rijndael_doc_V2.pdf (4.2.3)
mixed_columns = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]


class AES:
    """Standard input consists of a key to use, followed by
    one or more blocks to encrypt using that key. The 128-bit
    key is given as the first 16 bytes of the file. The first
    byte gives the first 8 bits, and so on. Each block consists
    of exactly 16 bytes. There are at most 10^6 blocks to
    encrypt.
    """
    def __init__(self, key_block, data_blocks):
        self.block_size = 16
        self.key_length = 16
        self.rounds = 10        # 10 rounds for 128-bit keys, 12 rounds for 192-bit keys, and 14 rounds for 256-bit keys

        self.original_key = key_block
        self.key = self.key_expansion(key_block)
        self.data = data_blocks

    def sub_and_rot_word(self, word):
        """Substitute each byte in the word with the corresponding byte in the s_box,
        then rotate the word one byte to the left.
        """
        word = word[1:] + word[:1]
        return [s_box[b] for b in word]

    def key_expansion(self, key):
        """
        4 Rijndael Key Expansion - https://www2.rivier.edu/journal/roaj-fall-2010/j455-selent-aes.pdf
        The original cipher key needs to be expanded from 16 bytes to 16*(r + 1) bytes. In the example, there are
        ten rounds so r = 10. A round key is needed after each round and before the first round. Each round key
        needs to be 16 bytes because the block size is 16 bytes. Therefore, the cipher key needs to be expanded
        from 16 bytes to 16*(r + 1) bytes or 176 bytes. The expanded key is then broken up into round keys.
        Round keys are added to the current state after each round and before the first round. The details on the
        key expansion algorithm are complex and will be skipped.
        """

        # key_symbols = [ord(char) for char in key]
        key_symbols = [b for b in key]

        w = [key_symbols[i:i + 4] for i in range(0, len(key_symbols), 4)]

        for i in range(4, 4 * 11):  # For AES-128, we need 44 words in the expanded key.
            temp = w[i - 1]
            if i % 4 == 0:
                temp = self.sub_and_rot_word(temp)
                temp[0] ^= r_con[i // 4 - 1][0]
            w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

        return w

    def sub_bytes(self, state):
        return [[s_box[byte] for byte in word] for word in state]

    def shift_rows(self, state):
        return [state[i][i:] + state[i][:i] for i in range(len(state))]

    def add_round_key(self, state, key):
        return [[byte ^ key[i][j] for j, byte in enumerate(word)] for i, word in enumerate(state)]

    def multiply(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x11b  # x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p % 256

    def mix_columns(self, state):
        """
        4.2.3 The MixColumn transformation - https://www.cs.miami.edu/home/burt/learning/Csc688.012/rijndael/rijndael_doc_V2.pdf
        In MixColumn, the columns of the State are considered as polynomials over GF(2^8) and
        multiplied modulo x^4+ 1 with a fixed polynomial c(x )
        """
        result = [[0 for _ in range(4)] for _ in range(4)]
        for c in range(4):
            for r in range(4):
                # Accumulate the results with bitwise XOR instead of integer sum
                value = 0
                for i in range(4):
                    value ^= self.multiply(mixed_columns[r][i], state[i][c])
                result[r][c] = value

        return result

    def aes_encrypt(self, block):
        state = [list(block[i:i + 4]) for i in range(0, len(block), 4)]
        state = self.add_round_key(state, self.key[:4])

        for current_round in range(1, self.rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.key[current_round * 4: (current_round + 1) * 4])

        # Final Round
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.key[40:])

        return state

    def encrypt(self):
        for block in self.data:
            encrypted_block = self.aes_encrypt(block)
            print("".join([f"{byte:02x}" for word in encrypted_block for byte in word]).upper())


def parse_input_from_file(file_path):
    with open(file_path, 'rb') as file:
        key = file.read(16)
        blocks = []
        block = file.read(16)

        while block:
            blocks.append(block)
            block = file.read(16)

    print("Key:", ''.join([f'{byte:02x}' for byte in key]).upper())

    return key, blocks


def read_input():
    key = sys.stdin.buffer.read(16)
    if not key:
        raise ValueError("Key not provided")

    data_blocks = []

    while True:
        block = sys.stdin.buffer.read(16)
        if not block:
            break
        if len(block) != 16:
            raise ValueError("Data block size incorrect. Each block must be exactly 16 bytes.")
        data_blocks.append(block)

    return key, data_blocks


if __name__ == "__main__":
    file_path = os.path.join(os.path.dirname(__file__), "aes_sample.in")
    if os.path.exists(file_path):
        key, blocks = parse_input_from_file(file_path)
    else:
        key, blocks = read_input()

    aes = AES(key, blocks)
    aes.encrypt()

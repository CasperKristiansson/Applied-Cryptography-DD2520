use std::io::{self, Read, Write};

// S-Box https://www2.rivier.edu/journal/roaj-fall-2010/j455-selent-aes.pdf
// Non-Linearity: The S-Box is a non-linear substitution table that operates on individual bytes.
// We use S-Box because it allows for avalanche effect, which means that a small change in the input
// (e.g., one bit) results in a large change in the output.
static S_BOX: [u8; 256] = [
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
];

// Constants are derived from the powers of 2 in the finite field GF(2^8)
// Prevents attacks based on the symmetries in the cipher's structure
static R_CON: [u8; 10] = [
    0x01,   // round 1: 2^0
    0x02,   // round 2: 2^1
    0x04,   // round 3: 2^2
    0x08,   // round 4: 2^3
    0x10,   // round 5: 2^4
    0x20,   // round 6: 2^5
    0x40,   // round 7: 2^6
    0x80,   // round 8: 2^7
    0x1b,   // round 9: 2^4 + 2^3 + 2^1 + 2^0
    0x36    // round 10: 2^5 + 2^4 + 2^1
];

struct AES {
    key: Vec<Vec<u8>>,
}

/*
Standard input consists of a key to use, followed by
one or more blocks to encrypt using that key. The 128-bit
key is given as the first 16 bytes of the file. The first
byte gives the first 8 bits, and so on. Each block consists
of exactly 16 bytes. There are at most 10^6 blocks to
encrypt.
*/
impl AES {
    fn new(key: Vec<u8>) -> Self {
        let expanded_key = AES::key_expansion(key);
        AES { key: expanded_key }
    }

    /*
    4 Rijndael Key Expansion - https://www2.rivier.edu/journal/roaj-fall-2010/j455-selent-aes.pdf
    The original cipher key needs to be expanded from 16 bytes to 16*(r + 1) bytes. In the example, there are
    ten rounds so r = 10. A round key is needed after each round and before the first round. Each round key
    needs to be 16 bytes because the block size is 16 bytes. Therefore, the cipher key needs to be expanded
    from 16 bytes to 16*(r + 1) bytes or 176 bytes. The expanded key is then broken up into round keys.
    Round keys are added to the current state after each round and before the first round. The details on the
    key expansion algorithm are complex and will be skipped. 128 (10), 192 (12), and 256 (14) bits
    */
    fn key_expansion(key: Vec<u8>) -> Vec<Vec<u8>> {
        let mut w: Vec<Vec<u8>> = Vec::new();
        for i in 0..4 {
            w.push(key[i*4..(i+1)*4].to_vec());
        }

        for i in 4..44 {                        // For AES-128, we need 44 words in the expanded key.
            let mut temp = w[i-1].clone();
            if i % 4 == 0 {
                temp = AES::sub_and_rot_word(&temp);
                temp[0] ^= R_CON[i / 4 - 1];
            }
            let mut new_word = Vec::new();
            for j in 0..4 {
                new_word.push(w[i-4][j] ^ temp[j]);
            }
            w.push(new_word);
        }
        w
    }

    /*
    Substitute each byte in the word with the corresponding byte in the s_box,
    then rotate the word one byte to the left.
    */
    fn sub_and_rot_word(word: &Vec<u8>) -> Vec<u8> {
        let mut new_word = word[1..].to_vec();
        new_word.push(word[0]);
        new_word.iter().map(|&b| S_BOX[b as usize]).collect()
    }

    fn sub_bytes(&self, state: &mut Vec<Vec<u8>>) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = S_BOX[state[i][j] as usize];
            }
        }
    }

    fn shift_rows(&self, state: &mut Vec<Vec<u8>>) {
        let mut temp = state[0][1];
        state[0][1] = state[1][1];
        state[1][1] = state[2][1];
        state[2][1] = state[3][1];
        state[3][1] = temp;

        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;
        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;

        temp = state[0][3];
        state[0][3] = state[3][3];
        state[3][3] = state[2][3];
        state[2][3] = state[1][3];
        state[1][3] = temp;
    }

    fn add_round_key(&self, state: &mut Vec<Vec<u8>>, round: usize) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] ^= self.key[round * 4 + i][j];
            }
        }
    }

    fn shift_if_can(a: u8) -> u8 {
        if a & 0x80 != 0 {
            ((a << 1) ^ 0x1B) & 0xFF
        } else {
            a << 1
        }
    }    

    /*
    4.2.3 The MixColumn transformation - https://www.cs.miami.edu/home/burt/learning/Csc688.012/rijndael/rijndael_doc_V2.pdf
    In MixColumn, the columns of the State are considered as polynomials over GF(2^8) and
    multiplied modulo x^4+1 with a fixed polynomial c(x)
    */
    fn mix_columns(&self, state: &mut Vec<Vec<u8>>) {
        for i in 0..4 {
            let t = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
            let u = state[i][0];

            for j in 0..3 {
                state[i][j] = state[i][j] ^ t ^ AES::shift_if_can(state[i][j] ^ state[i][(j + 1) % 4]);
            }
            state[i][3] = state[i][3] ^ t ^ AES::shift_if_can(state[i][3] ^ u);
        }
    }

    fn encrypt(&self, block: Vec<u8>) -> Vec<Vec<u8>> {
        let mut state: Vec<Vec<u8>> = Vec::new();
        for i in 0..4 {
            state.push(block[i*4..(i+1)*4].to_vec());
        }

        self.add_round_key(&mut state, 0);

        for round in 1..10 {
            self.sub_bytes(&mut state);             // Substitution
            self.shift_rows(&mut state);            // Permutation
            self.mix_columns(&mut state);           // Diffusion / Permutation
            self.add_round_key(&mut state, round);
        }

        // // Final round
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, 10);

        state
    }
}

fn run_kattis() {
    let mut key = vec![0u8; 16];
    let _ = io::stdin().read_exact(&mut key);

    let aes = AES::new(key);

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let mut block_buffer = [0u8; 16];
    while let Ok(_) = io::stdin().read_exact(&mut block_buffer) {
        let block = block_buffer.to_vec();
        let encrypted_block = aes.encrypt(block);

        for byte in encrypted_block.iter().flat_map(|byte| byte) {
            handle.write_all(&[*byte]).unwrap();
        }

        // for byte in encrypted_block {
        //     for b in byte {
        //         print!("{:02X}", b);
        //     }
        // }
    }
}

fn main() {
    run_kattis();
}

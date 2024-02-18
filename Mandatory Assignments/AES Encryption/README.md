# AES

AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used across the globe to secure data. It was established as an encryption standard by the U.S. National Institute of Standards and Technology (NIST) in 2001, after a 5-year standardization process. AES is based on the Rijndael encryption algorithm, designed by two Belgian cryptographers, Vincent Rijmen and Joan Daemen.

Here’s a simplified overview of how AES works:

### Key Features
- **Symmetric Key Encryption**: The same key is used for both encrypting and decrypting data, which requires secure key management practices.
- **Block Cipher**: AES encrypts data in fixed-size blocks (128 bits), making it a block cipher. It means the original data is divided into blocks of equal size, and each block is encrypted separately.
- **Key Sizes**: AES supports three key sizes: 128, 192, and 256 bits. The choice of key size determines the number of rounds of transformation that the data will undergo. More rounds offer higher security but can impact performance.

### Encryption Process
1. **Key Expansion**: The chosen key is expanded into several round keys using the Rijndael key schedule. The number of rounds depends on the key size: 10 rounds for 128-bit keys, 12 rounds for 192-bit keys, and 14 rounds for 256-bit keys.
2. **Initial Round**:
   - **AddRoundKey**: Each byte of the block is combined with the round key using bitwise XOR.
3. **Main Rounds**: Each main round consists of four steps:
   - **SubBytes**: A non-linear substitution step where each byte is replaced with another according to a lookup table (S-box).
   - **ShiftRows**: A transposition step where each row of the block is shifted cyclically a certain number of steps.
   - **MixColumns**: A mixing operation which operates on the columns of the block, combining the four bytes in each column.
   - **AddRoundKey**: Each byte of the block is combined again with the round key using bitwise XOR.
4. **Final Round**:
   - The final round is similar to the main rounds but omits the MixColumns step.

### Decryption Process
AES decryption is not merely the encryption process in reverse. While it uses the same steps, they are applied in reverse order, and some steps use inverse functions, such as InvShiftRows and InvSubBytes, to restore the original plaintext from the ciphertext.

### Security
AES is considered highly secure. Its widespread adoption in government and financial industry standards attests to its security level. It is used in various applications, including securing file storage, VPN connections, and internet communications.

The design and strength of AES lie in its simplicity, efficiency across various platforms, resistance to all known attacks (except for brute force attacks, which are mitigated by using sufficiently long keys), and its ability to be implemented in both hardware and software efficiently.